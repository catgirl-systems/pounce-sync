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

type SignedEntry struct{ Entry, Sig []byte }

// AppendRoster checks the head precondition, applies the entries in order to the
// roster loaded in the same transaction, then stores them with their effects.
// the batch may not leave a rotate pending, and a batch that rotates carries the
// new epoch key for every recipient, so a removed device's epoch is never current
// once its removal commits, and a rotate never commits without its keys.
func (s *Store) AppendRoster(ctx context.Context, accountID []byte, ifMatch uint64, entries []SignedEntry, keys []WrappedKey) (uint64, error) {
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
		start := st.Epoch
		var effects [][]any
		for _, se := range entries {
			e, err := st.Apply(se.Entry, se.Sig)
			if err != nil {
				return ErrInvalid
			}
			head = e.Index
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
			effects = append(effects, []any{"INSERT INTO roster(account_id, idx, entry, sig, hash) VALUES (?, ?, ?, ?, ?)",
				accountID, int64(e.Index), se.Entry, se.Sig, st.HeadHash})
		}
		if st.RotatePending || !epochKeys(st, start, accountID, keys) {
			return ErrInvalid
		}
		for _, k := range keys {
			effects = append(effects, []any{"INSERT INTO wrapped_keys(account_id, recipient_id, epoch, blob, signer_id, sig) VALUES (?, ?, ?, ?, ?, ?)",
				accountID, k.RecipientID, k.Epoch, k.Blob, k.SignerID, k.Sig})
		}
		effects = append(effects, []any{"UPDATE accounts SET roster_head = ?, epoch = ?, rotate_pending = ? WHERE id = ?",
			int64(head), st.Epoch, st.RotatePending, accountID})
		return execAll(ctx, tx, effects)
	})
	return head, err
}

// epochKeys reports whether keys is exactly what the batch needs: nothing when the
// epoch did not change, otherwise one key at the new epoch for each active device
// and the recovery key, each signed by an active device.
func epochKeys(st *roster.State, start uint32, accountID []byte, keys []WrappedKey) bool {
	if st.Epoch == start {
		return len(keys) == 0
	}
	want := map[string]bool{string(st.RecoveryID): true}
	for id, m := range st.Devices {
		if m.Active {
			want[id] = true
		}
	}
	if len(keys) != len(want) {
		return false
	}
	for _, k := range keys {
		signer := st.Devices[string(k.SignerID)]
		if !want[string(k.RecipientID)] || k.Epoch != st.Epoch || signer == nil || !signer.Active ||
			!roster.Verify(signer.SignPub, roster.WrappedKeyMessage(accountID, k.RecipientID, k.Epoch, k.Blob), k.Sig) {
			return false
		}
		// a second key for the same recipient fails the lookup above.
		delete(want, string(k.RecipientID))
	}
	return true
}
