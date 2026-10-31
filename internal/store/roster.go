package store

import (
	"context"
	"database/sql"

	"pounce-sync/internal/roster"
)

type RosterEntry struct {
	Index      uint64
	Entry, Sig []byte
}

func (s *Store) Roster(ctx context.Context, accountID []byte, from uint64) (uint64, []RosterEntry, error) {
	var head uint64
	err := s.db.QueryRowContext(ctx, "SELECT roster_head FROM accounts WHERE id = ?", accountID).Scan(&head)
	if err != nil {
		return 0, nil, notFound(err, ErrNotFound)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT idx, entry, sig FROM roster
		WHERE account_id = ? AND idx >= ? AND idx <= ? ORDER BY idx LIMIT ?`, accountID, int64(from), head, rosterPage)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	entries := []RosterEntry{}
	for rows.Next() {
		var e RosterEntry
		if err := rows.Scan(&e.Index, &e.Entry, &e.Sig); err != nil {
			return 0, nil, err
		}
		entries = append(entries, e)
	}
	return head, entries, rows.Err()
}

func loadState(ctx context.Context, tx *sql.Tx, accountID []byte) (*roster.State, error) {
	st := &roster.State{AccountID: accountID, Devices: map[string]*roster.Member{}}
	var head uint64
	err := tx.QueryRowContext(ctx, `SELECT a.roster_head, a.epoch, a.rotate_pending, a.recovery_id, r.hash FROM accounts a
		JOIN roster r ON r.account_id = a.id AND r.idx = a.roster_head WHERE a.id = ?`, accountID).
		Scan(&head, &st.Epoch, &st.RotatePending, &st.RecoveryID, &st.HeadHash)
	if err != nil {
		return nil, notFound(err, ErrNotFound)
	}
	st.Count = head + 1
	rows, err := tx.QueryContext(ctx, "SELECT device_id, kind, sign_pub, active FROM devices WHERE account_id = ?", accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, pub []byte
		var kind string
		var active bool
		if err := rows.Scan(&id, &kind, &pub, &active); err != nil {
			return nil, err
		}
		if kind == "recovery" {
			st.RecoveryPub = pub
		} else {
			st.Devices[string(id)] = &roster.Member{SignPub: pub, Active: active}
		}
	}
	return st, rows.Err()
}

// AppendRoster checks the head precondition, applies the entry to the roster
// loaded in the same transaction, then stores it with its effects.
func (s *Store) AppendRoster(ctx context.Context, accountID []byte, ifMatch uint64, entry, sig []byte) (uint64, error) {
	var head uint64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		st, err := loadState(ctx, tx, accountID)
		if err != nil {
			return err
		}
		head = st.Count - 1
		if head != ifMatch {
			return ErrPrecondition
		}
		e, err := st.Apply(entry, sig)
		if err != nil {
			return ErrInvalid
		}
		head = e.Index
		var effects [][]any
		switch e.Action {
		case "add_device":
			effects = append(effects, []any{insertDevice, accountID, e.Device.ID, e.Device.SignPub})
		case "remove_device":
			effects = append(effects, []any{"UPDATE devices SET active = 0 WHERE account_id = ? AND device_id = ?", accountID, e.TargetID})
		case "recover":
			effects = append(effects,
				[]any{"UPDATE devices SET active = 0 WHERE account_id = ? AND kind = 'device'", accountID},
				[]any{insertDevice, accountID, e.Device.ID, e.Device.SignPub})
		}
		effects = append(effects,
			[]any{"INSERT INTO roster(account_id, idx, entry, sig, hash) VALUES (?, ?, ?, ?, ?)", accountID, int64(e.Index), entry, sig, st.HeadHash},
			[]any{"UPDATE accounts SET roster_head = ?, epoch = ?, rotate_pending = ? WHERE id = ?", int64(e.Index), st.Epoch, st.RotatePending, accountID})
		return execAll(ctx, tx, effects)
	})
	return head, err
}
