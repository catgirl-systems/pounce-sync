package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"time"

	"pounce-sync/internal/roster"
)

func (s *Store) CreatePairing(ctx context.Context, accountID, deviceID, authHash []byte, now time.Time) ([]byte, error) {
	id := random(16)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := devicePub(ctx, tx, accountID, deviceID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO pairings(id, account_id, auth_hash, expires_at) VALUES (?, ?, ?, ?)",
			id, accountID, authHash, now.Add(PairingTTL).Unix())
		return err
	})
	return id, err
}

// JoinPairing checks, in order: the pairing exists and is unexpired (404), the
// auth token hashes to auth_hash in constant time (403), nobody joined yet (409).
func (s *Store) JoinPairing(ctx context.Context, id, authToken, payload []byte, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var authHash []byte
		var joined bool
		err := tx.QueryRowContext(ctx, "SELECT auth_hash, payload IS NOT NULL FROM pairings WHERE id = ? AND expires_at > ?",
			id, now.Unix()).Scan(&authHash, &joined)
		if err != nil {
			return notFound(err, ErrNotFound)
		}
		if subtle.ConstantTimeCompare(hash(authToken), authHash) != 1 {
			return ErrForbidden
		}
		if joined {
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE pairings SET payload = ? WHERE id = ?", payload, id)
		return err
	})
}

// PairingPayload returns the joined payload, or nil while nobody has joined.
// the payload cannot change once set, since a second join is refused.
func (s *Store) PairingPayload(ctx context.Context, accountID, id []byte, now time.Time) ([]byte, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM pairings WHERE id = ? AND account_id = ? AND expires_at > ?",
		id, accountID, now.Unix()).Scan(&payload)
	return payload, notFound(err, ErrNotFound)
}

// SetPairingNonce stores the existing device's signed nonce, once, after a join:
// the joined payload is fixed before the nonce exists, so it cannot be ground
// against the short code. the signature covers the payload hash.
func (s *Store) SetPairingNonce(ctx context.Context, accountID, deviceID, id, nonce, sig []byte, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		pub, err := devicePub(ctx, tx, accountID, deviceID)
		if err != nil {
			return err
		}
		var payload []byte
		var set bool
		err = tx.QueryRowContext(ctx, "SELECT payload, nonce IS NOT NULL FROM pairings WHERE id = ? AND account_id = ? AND expires_at > ?",
			id, accountID, now.Unix()).Scan(&payload, &set)
		if err != nil {
			return notFound(err, ErrNotFound)
		}
		if payload == nil || set {
			return ErrConflict
		}
		if !roster.Verify(pub, roster.PairingNonceMessage(accountID, id, hash(payload), nonce), sig) {
			return ErrForbidden
		}
		_, err = tx.ExecContext(ctx, "UPDATE pairings SET nonce = ?, signer_id = ?, nonce_sig = ? WHERE id = ?", nonce, deviceID, sig, id)
		return err
	})
}

type PairingNonce struct{ Nonce, SignerID, Sig []byte }

// PollPairing gives the joining device the signed nonce and deletes the pairing,
// or returns nil while the nonce is not set. errors as in JoinPairing (404, 403).
func (s *Store) PollPairing(ctx context.Context, id, authToken []byte, now time.Time) (*PairingNonce, error) {
	var out *PairingNonce
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var authHash []byte
		var n PairingNonce
		err := tx.QueryRowContext(ctx, "SELECT auth_hash, nonce, signer_id, nonce_sig FROM pairings WHERE id = ? AND expires_at > ?",
			id, now.Unix()).Scan(&authHash, &n.Nonce, &n.SignerID, &n.Sig)
		if err != nil {
			return notFound(err, ErrNotFound)
		}
		if subtle.ConstantTimeCompare(hash(authToken), authHash) != 1 {
			return ErrForbidden
		}
		if n.Nonce == nil {
			return nil
		}
		out = &n
		_, err = tx.ExecContext(ctx, "DELETE FROM pairings WHERE id = ?", id)
		return err
	})
	return out, err
}
