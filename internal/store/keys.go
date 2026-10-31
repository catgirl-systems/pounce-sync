package store

import (
	"context"
	"database/sql"

	"pounce-sync/internal/roster"
)

type WrappedKey struct {
	RecipientID []byte
	Epoch       uint32
	Blob        []byte
	SignerID    []byte
	Sig         []byte
}

// PutKey stores a wrapped key signed by the session's own device for an active
// device or the recovery key, at an epoch between 1 and the current one.
func (s *Store) PutKey(ctx context.Context, accountID []byte, k WrappedKey) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var epoch uint32
		var pub []byte
		var recipient bool
		err := tx.QueryRowContext(ctx, `SELECT a.epoch, d.sign_pub,
			EXISTS (SELECT 1 FROM devices WHERE account_id = a.id AND device_id = ? AND active = 1)
			FROM accounts a JOIN devices d ON d.account_id = a.id
			WHERE a.id = ? AND d.device_id = ? AND d.kind = 'device' AND d.active = 1`, k.RecipientID, accountID, k.SignerID).Scan(&epoch, &pub, &recipient)
		if err != nil {
			return notFound(err, ErrUnauthorized)
		}
		if !recipient || k.Epoch < 1 || k.Epoch > epoch ||
			!roster.Verify(pub, roster.WrappedKeyMessage(accountID, k.RecipientID, k.Epoch, k.Blob), k.Sig) {
			return ErrInvalid
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO wrapped_keys(account_id, recipient_id, epoch, blob, signer_id, sig)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (account_id, recipient_id, epoch)
			DO UPDATE SET blob = excluded.blob, signer_id = excluded.signer_id, sig = excluded.sig`,
			accountID, k.RecipientID, k.Epoch, k.Blob, k.SignerID, k.Sig)
		return err
	})
}

func (s *Store) GetKey(ctx context.Context, accountID, recipientID []byte, epoch uint32) (*WrappedKey, error) {
	k := &WrappedKey{RecipientID: recipientID, Epoch: epoch}
	err := s.db.QueryRowContext(ctx, `SELECT blob, signer_id, sig FROM wrapped_keys
		WHERE account_id = ? AND recipient_id = ? AND epoch = ?`, accountID, recipientID, epoch).Scan(&k.Blob, &k.SignerID, &k.Sig)
	if err != nil {
		return nil, notFound(err, ErrNotFound)
	}
	return k, nil
}
