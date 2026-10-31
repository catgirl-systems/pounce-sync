package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrPrecondition  = errors.New("precondition failed")
	ErrInvalid       = errors.New("invalid entry")
	ErrForbidden     = errors.New("forbidden")
	ErrQuota         = errors.New("quota exceeded")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrTooLarge      = errors.New("too large")
	ErrRotatePending = errors.New("rotate pending")
)

const (
	SessionTTL   = time.Hour
	challengeTTL = time.Minute
	PairingTTL   = 10 * time.Minute
	maxEnvelope  = 64 << 10
	maxPageBytes = 1 << 20
	rosterPage   = 1000
)

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
	id             BLOB PRIMARY KEY,
	head_seq       INTEGER NOT NULL DEFAULT 0,
	roster_head    INTEGER NOT NULL,
	epoch          INTEGER NOT NULL,
	rotate_pending INTEGER NOT NULL DEFAULT 0,
	recovery_id    BLOB NOT NULL,
	created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS roster (
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	idx        INTEGER NOT NULL,
	entry      BLOB NOT NULL,
	sig        BLOB NOT NULL,
	hash       BLOB NOT NULL,
	PRIMARY KEY (account_id, idx)
);
CREATE TABLE IF NOT EXISTS devices (
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	device_id  BLOB NOT NULL,
	kind       TEXT NOT NULL CHECK (kind IN ('device', 'recovery')),
	sign_pub   BLOB NOT NULL,
	active     INTEGER NOT NULL,
	PRIMARY KEY (account_id, device_id)
);
CREATE TABLE IF NOT EXISTS wrapped_keys (
	account_id   BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	recipient_id BLOB NOT NULL,
	epoch        INTEGER NOT NULL,
	blob         BLOB NOT NULL,
	signer_id    BLOB NOT NULL,
	sig          BLOB NOT NULL,
	PRIMARY KEY (account_id, recipient_id, epoch)
);
CREATE TABLE IF NOT EXISTS records (
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	record_id  BLOB NOT NULL,
	rev        INTEGER NOT NULL,
	seq        INTEGER NOT NULL,
	epoch      INTEGER NOT NULL,
	blob       BLOB NOT NULL,
	PRIMARY KEY (account_id, record_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS records_seq ON records (account_id, seq);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash BLOB PRIMARY KEY,
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	device_id  BLOB NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
	nonce      BLOB PRIMARY KEY,
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	device_id  BLOB NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pairings (
	id         BLOB PRIMARY KEY,
	account_id BLOB NOT NULL REFERENCES accounts ON DELETE CASCADE,
	auth_hash  BLOB NOT NULL,
	payload    BLOB,
	nonce      BLOB,
	signer_id  BLOB,
	nonce_sig  BLOB,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
	token_hash BLOB PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions (account_id);
CREATE INDEX IF NOT EXISTS challenges_account ON challenges (account_id);
CREATE INDEX IF NOT EXISTS pairings_account ON pairings (account_id);
`

type Store struct{ db *sql.DB }

// fileURI escapes path so SQLite reads it literally: the connection uses URI
// filenames, where '?', '#' and '%' would otherwise be interpreted.
func fileURI(path, query string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: "file", Path: abs, RawQuery: query}).String(), nil
}

func Open(path string) (*Store, error) {
	dsn, err := fileURI(path, "_journal_mode=WAL&_foreign_keys=1&_busy_timeout=10000&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// rotate_pending came after the first schema: add it to databases that predate it.
	var n int
	err = db.QueryRow("SELECT count(*) FROM pragma_table_info('accounts') WHERE name = 'rotate_pending'").Scan(&n)
	if err == nil && n == 0 {
		_, err = db.Exec("ALTER TABLE accounts ADD COLUMN rotate_pending INTEGER NOT NULL DEFAULT 0")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// execAll runs statements given as {query, args...}.
func execAll(ctx context.Context, tx *sql.Tx, stmts [][]any) error {
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q[0].(string), q[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func notFound(err error, as error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return as
	}
	return err
}

// devicePub runs inside write transactions, so a request that started before
// its device was removed cannot write once the removal has committed.
func devicePub(ctx context.Context, tx *sql.Tx, accountID, deviceID []byte) ([]byte, error) {
	var pub []byte
	err := tx.QueryRowContext(ctx, "SELECT sign_pub FROM devices WHERE account_id = ? AND device_id = ? AND kind = 'device' AND active = 1",
		accountID, deviceID).Scan(&pub)
	return pub, notFound(err, ErrUnauthorized)
}

const insertDevice = "INSERT INTO devices(account_id, device_id, kind, sign_pub, active) VALUES (?, ?, 'device', ?, 1)"

func (s *Store) CreateInvite(ctx context.Context, ttl time.Duration) (string, error) {
	tok := random(32)
	_, err := s.db.ExecContext(ctx, "INSERT INTO invites(token_hash, expires_at) VALUES (?, ?)",
		hash(tok), time.Now().Add(ttl).Unix())
	return base64.RawURLEncoding.EncodeToString(tok), err
}

func (s *Store) Sweep(ctx context.Context, now time.Time) error {
	for _, t := range []string{"challenges", "sessions", "pairings", "invites"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+t+" WHERE expires_at <= ?", now.Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Stats(ctx context.Context) (accounts, records, blobBytes int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM accounts),
		(SELECT count(*) FROM records), (SELECT coalesce(sum(length(blob)), 0) FROM records)`).
		Scan(&accounts, &records, &blobBytes)
	return
}

func (s *Store) Backup(ctx context.Context, path string) error {
	uri, err := fileURI(path, "")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "VACUUM INTO ?", uri)
	return err
}
