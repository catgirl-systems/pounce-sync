package store

import (
	"bytes"
	"context"
	"database/sql"
	"time"

	"pounce-sync/internal/roster"
)

type Session struct {
	AccountID, DeviceID []byte
	Recovery            bool
}

// CreateAccount verifies the genesis entry and the two epoch-1 wrapped keys, then
// in one transaction consumes the invite (when inviteHash is not nil) and inserts the account.
func (s *Store) CreateAccount(ctx context.Context, accountID, entry, sig []byte, keys []WrappedKey, inviteHash []byte, now time.Time) error {
	st := &roster.State{AccountID: accountID}
	e, err := st.Apply(entry, sig)
	if err != nil {
		return ErrInvalid
	}
	dev := e.Device
	if len(keys) != 2 || bytes.Equal(keys[0].RecipientID, keys[1].RecipientID) {
		return ErrInvalid
	}
	for _, k := range keys {
		if (!bytes.Equal(k.RecipientID, dev.ID) && !bytes.Equal(k.RecipientID, e.RecoveryID)) ||
			k.Epoch != 1 || !bytes.Equal(k.SignerID, dev.ID) ||
			!roster.Verify(dev.SignPub, roster.WrappedKeyMessage(accountID, k.RecipientID, 1, k.Blob), k.Sig) {
			return ErrInvalid
		}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO accounts(id, roster_head, epoch, recovery_id, created_at)
			VALUES (?, 0, 1, ?, ?) ON CONFLICT DO NOTHING`, accountID, e.RecoveryID, now.Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrConflict
		}
		if inviteHash != nil {
			var one int
			err := tx.QueryRowContext(ctx, "DELETE FROM invites WHERE token_hash = ? AND expires_at > ? RETURNING 1", inviteHash, now.Unix()).Scan(&one)
			if err != nil {
				return notFound(err, ErrForbidden)
			}
		}
		stmts := [][]any{
			{"INSERT INTO roster(account_id, idx, entry, sig, hash) VALUES (?, 0, ?, ?, ?)",
				accountID, entry, sig, st.HeadHash},
			{insertDevice, accountID, dev.ID, dev.SignPub},
			{"INSERT INTO devices(account_id, device_id, kind, sign_pub, active) VALUES (?, ?, 'recovery', ?, 1)",
				accountID, e.RecoveryID, e.RecoverySignPub},
		}
		for _, k := range keys {
			stmts = append(stmts, []any{"INSERT INTO wrapped_keys(account_id, recipient_id, epoch, blob, signer_id, sig) VALUES (?, ?, 1, ?, ?, ?)",
				accountID, k.RecipientID, k.Blob, k.SignerID, k.Sig})
		}
		return execAll(ctx, tx, stmts)
	})
}

// Challenge issues a nonce only for an active device or recovery key of the account.
func (s *Store) Challenge(ctx context.Context, accountID, deviceID []byte, now time.Time) ([]byte, error) {
	nonce := random(32)
	var one int
	err := s.db.QueryRowContext(ctx, `INSERT INTO challenges(nonce, account_id, device_id, expires_at)
		SELECT ?, account_id, device_id, ? FROM devices WHERE account_id = ? AND device_id = ? AND active = 1 RETURNING 1`,
		nonce, now.Add(challengeTTL).Unix(), accountID, deviceID).Scan(&one)
	return nonce, notFound(err, ErrUnauthorized)
}

// Login consumes the challenge in its own statement first, so a bad signature
// still burns it, then checks the signature and creates a session. it returns the raw token.
func (s *Store) Login(ctx context.Context, accountID, deviceID, nonce, sig []byte, origin string, now time.Time) ([]byte, error) {
	var acct, dev []byte
	var exp int64
	err := s.db.QueryRowContext(ctx, "DELETE FROM challenges WHERE nonce = ? RETURNING account_id, device_id, expires_at",
		nonce).Scan(&acct, &dev, &exp)
	if err != nil {
		return nil, notFound(err, ErrUnauthorized)
	}
	if !bytes.Equal(acct, accountID) || !bytes.Equal(dev, deviceID) || exp <= now.Unix() {
		return nil, ErrUnauthorized
	}
	token := random(32)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var pub []byte
		err := tx.QueryRowContext(ctx, "SELECT sign_pub FROM devices WHERE account_id = ? AND device_id = ? AND active = 1",
			accountID, deviceID).Scan(&pub)
		if err != nil {
			return notFound(err, ErrUnauthorized)
		}
		if !roster.Verify(pub, roster.AuthMessage(origin, accountID, deviceID, nonce), sig) {
			return ErrUnauthorized
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO sessions(token_hash, account_id, device_id, expires_at) VALUES (?, ?, ?, ?)",
			hash(token), accountID, deviceID, now.Add(SessionTTL).Unix())
		return err
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Session resolves a token hash; it fails as soon as the device is no longer active.
func (s *Store) Session(ctx context.Context, tokenHash []byte, now time.Time) (*Session, error) {
	ses := &Session{}
	var kind string
	err := s.db.QueryRowContext(ctx, `SELECT s.account_id, s.device_id, d.kind FROM sessions s
		JOIN devices d ON d.account_id = s.account_id AND d.device_id = s.device_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND d.active = 1`, tokenHash, now.Unix()).
		Scan(&ses.AccountID, &ses.DeviceID, &kind)
	if err != nil {
		return nil, notFound(err, ErrUnauthorized)
	}
	ses.Recovery = kind == "recovery"
	return ses, nil
}

// DeleteAccount checks the delete-account signature of the session's device over
// the current roster head, then removes the account; every other table follows
// by ON DELETE CASCADE.
func (s *Store) DeleteAccount(ctx context.Context, accountID, deviceID, sig []byte, origin string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var pub, head []byte
		err := tx.QueryRowContext(ctx, `SELECT d.sign_pub, r.hash FROM accounts a
			JOIN devices d ON d.account_id = a.id JOIN roster r ON r.account_id = a.id AND r.idx = a.roster_head
			WHERE a.id = ? AND d.device_id = ? AND d.kind = 'device' AND d.active = 1`, accountID, deviceID).Scan(&pub, &head)
		if err != nil {
			return notFound(err, ErrUnauthorized)
		}
		if !roster.Verify(pub, roster.DeleteMessage(origin, accountID, deviceID, head), sig) {
			return ErrForbidden
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM accounts WHERE id = ?", accountID)
		return err
	})
}
