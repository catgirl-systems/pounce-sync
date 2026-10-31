package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"pounce-sync/internal/store"
)

// b64 is binary carried as canonical base64url without padding; anything else fails to decode.
type b64 []byte

func (b b64) MarshalText() ([]byte, error) {
	return []byte(base64.RawURLEncoding.EncodeToString(b)), nil
}

func (b *b64) UnmarshalText(t []byte) error {
	v, err := base64.RawURLEncoding.DecodeString(string(t))
	if err != nil || base64.RawURLEncoding.EncodeToString(v) != string(t) {
		return errors.New("bad base64url")
	}
	*b = v
	return nil
}

func parseB64(s string, n int) ([]byte, bool) {
	var b b64
	if b.UnmarshalText([]byte(s)) != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

type wrappedKey struct {
	RecipientID b64    `json:"recipientID"`
	Epoch       uint32 `json:"epoch"`
	Blob        b64    `json:"blob"`
	SignerID    b64    `json:"signerID"`
	Sig         b64    `json:"sig"`
}

type record struct {
	ID   b64    `json:"id"`
	Rev  uint64 `json:"rev"`
	Seq  uint64 `json:"seq"`
	Blob b64    `json:"blob,omitempty"`
}

func toRecord(r *store.Record) *record {
	if r == nil {
		return nil
	}
	return &record{ID: r.ID, Rev: r.Rev, Seq: r.Seq, Blob: r.Blob}
}

func reply(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
	return nil
}

func noContent(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// response fields are declared in json key order, so bodies encode exactly as
// maps would; clients see the same bytes.
type errorBody struct {
	Error string `json:"error"`
}

// headBody is the roster head after an append, or 0 for a new account.
type headBody struct {
	Head uint64 `json:"head"`
}

// httpError is a failure a handler returns; handle writes it as {"error": code}.
type httpError struct {
	status int
	code   string
}

func (e httpError) Error() string { return e.code }

var (
	errBadRequest   = httpError{http.StatusBadRequest, "bad_request"}
	errTooLarge     = httpError{http.StatusRequestEntityTooLarge, "too_large"}
	errForbidden    = httpError{http.StatusForbidden, "forbidden"}
	errRateLimited  = httpError{http.StatusTooManyRequests, "rate_limited"}
	errPrecondition = httpError{http.StatusPreconditionRequired, "precondition_required"}
)

// storeError maps a store sentinel to its HTTP status and code.
type storeError struct {
	err error
	httpError
}

var storeErrors = []storeError{
	{store.ErrNotFound, httpError{http.StatusNotFound, "not_found"}},
	{store.ErrConflict, httpError{http.StatusConflict, "conflict"}},
	{store.ErrPrecondition, httpError{http.StatusPreconditionFailed, "precondition_failed"}},
	{store.ErrInvalid, httpError{http.StatusUnprocessableEntity, "invalid_entry"}},
	{store.ErrForbidden, errForbidden},
	{store.ErrQuota, httpError{http.StatusForbidden, "quota_exceeded"}},
	{store.ErrUnauthorized, httpError{http.StatusUnauthorized, "unauthorized"}},
	{store.ErrTooLarge, errTooLarge},
}

// handle writes the error a handler returns; only unexpected ones are logged.
func handle(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var he httpError
		if !errors.As(err, &he) {
			he = httpError{http.StatusInternalServerError, "internal"}
			for _, e := range storeErrors {
				if errors.Is(err, e.err) {
					he = e.httpError
					break
				}
			}
		}
		if he.status == http.StatusInternalServerError && !errors.Is(err, context.Canceled) {
			slog.Error("internal error", "err", err)
		}
		reply(w, he.status, errorBody{he.code})
	}
}

// decode reads exactly one JSON object with no unknown fields, within limit bytes.
// field names match case-insensitively (encoding/json); every value is still checked.
func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		// the read past the object may hit the size limit: keep that error.
		switch _, e := dec.Token(); {
		case e == nil:
			err = errors.New("trailing data")
		case e != io.EOF:
			err = e
		}
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return errTooLarge
	case err != nil:
		return errBadRequest
	}
	return nil
}

// sized checks a blob is present and at most max bytes.
func sized(b []byte, max int) error {
	switch {
	case len(b) == 0:
		return errBadRequest
	case len(b) > max:
		return errTooLarge
	}
	return nil
}

// etag parses a quoted revision or roster head, `"7"`.
func etag(h string) (uint64, bool) {
	if len(h) < 3 || h[0] != '"' || h[len(h)-1] != '"' {
		return 0, false
	}
	n, err := strconv.ParseUint(h[1:len(h)-1], 10, 63)
	return n, err == nil
}

func intParam(s string, def, lo, hi int64) (int64, bool) {
	if s == "" {
		return def, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= lo && n <= hi
}
