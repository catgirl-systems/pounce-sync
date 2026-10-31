package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
)

type Record struct {
	ID   []byte
	Rev  uint64
	Seq  uint64
	Blob []byte
}

type Write struct {
	ID      []byte
	IfMatch uint64 // 0: the record must not exist
	Blob    []byte
}

type Failed struct {
	ID      []byte
	Current *Record // nil when the record does not exist
}

// envelopeEpoch checks the envelope header (version 1, 33 bytes to 64 KiB) and returns its epoch.
func envelopeEpoch(b []byte) (uint32, error) {
	if len(b) > maxEnvelope {
		return 0, ErrTooLarge
	}
	if len(b) < 33 || b[0] != 1 {
		return 0, ErrInvalid
	}
	return binary.BigEndian.Uint32(b[1:5]), nil
}

// Batch applies all writes or none: on ErrPrecondition it returns every failed
// write with its current record. written records come back without their blob.
func (s *Store) Batch(ctx context.Context, accountID, deviceID []byte, ws []Write, maxRecords int) (out []Record, failed []Failed, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		// the join also checks the device is still active, as in devicePub.
		var epoch uint32
		var head uint64
		var pending bool
		err := tx.QueryRowContext(ctx, `SELECT a.epoch, a.head_seq, a.rotate_pending FROM accounts a JOIN devices d ON d.account_id = a.id
			WHERE a.id = ? AND d.device_id = ? AND d.kind = 'device' AND d.active = 1`, accountID, deviceID).Scan(&epoch, &head, &pending)
		if err != nil {
			return notFound(err, ErrUnauthorized)
		}
		// a removed device still knows the current epoch's key, so nothing new is
		// written under it. only rosters appended before atomic rotation get here.
		if pending {
			return ErrRotatePending
		}
		creates := 0
		for _, w := range ws {
			e, err := envelopeEpoch(w.Blob)
			if err != nil {
				return err
			}
			if e != epoch {
				return ErrInvalid
			}
			cur := &Record{ID: w.ID}
			err = tx.QueryRowContext(ctx, "SELECT rev, seq, blob FROM records WHERE account_id = ? AND record_id = ?",
				accountID, w.ID).Scan(&cur.Rev, &cur.Seq, &cur.Blob)
			if errors.Is(err, sql.ErrNoRows) {
				cur = nil
				creates++
			} else if err != nil {
				return err
			}
			if (cur == nil && w.IfMatch != 0) || (cur != nil && cur.Rev != w.IfMatch) {
				failed = append(failed, Failed{ID: w.ID, Current: cur})
			}
		}
		if failed != nil {
			return ErrPrecondition
		}
		if creates > 0 {
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM records WHERE account_id = ?", accountID).Scan(&n); err != nil {
				return err
			}
			if n+creates > maxRecords {
				return ErrQuota
			}
		}
		out = make([]Record, len(ws))
		for i, w := range ws {
			head++
			out[i] = Record{ID: w.ID, Rev: w.IfMatch + 1, Seq: head}
			_, err := tx.ExecContext(ctx, `INSERT INTO records(account_id, record_id, rev, seq, epoch, blob) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (account_id, record_id) DO UPDATE SET rev = excluded.rev, seq = excluded.seq, epoch = excluded.epoch, blob = excluded.blob`,
				accountID, w.ID, int64(out[i].Rev), int64(head), epoch, w.Blob)
			if err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE accounts SET head_seq = ? WHERE id = ?", int64(head), accountID)
		return err
	})
	return out, failed, err
}

// Changes reads one row past limit to learn whether more records follow, and
// also ends the page early once it holds maxPageBytes of blobs (at least one record).
func (s *Store) Changes(ctx context.Context, accountID []byte, since int64, limit int) ([]Record, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record_id, rev, seq, blob FROM records
		WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?`, accountID, since, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	recs := []Record{}
	size := 0
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Rev, &r.Seq, &r.Blob); err != nil {
			return nil, false, err
		}
		if size += len(r.Blob); len(recs) > 0 && size > maxPageBytes {
			return recs, true, nil
		}
		recs = append(recs, r)
	}
	if len(recs) > limit {
		return recs[:limit], true, rows.Err()
	}
	return recs, false, rows.Err()
}
