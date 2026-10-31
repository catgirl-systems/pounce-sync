package api

import (
	"errors"
	"math"
	"net/http"

	"pounce-sync/internal/store"
)

type rosterResponse struct {
	Entries []rosterEntry `json:"entries"`
	Head    uint64        `json:"head"`
}

type staleHeadResponse struct {
	Error string `json:"error"`
	Head  uint64 `json:"head"`
}

type rosterEntry struct {
	Index uint64 `json:"index"`
	Entry b64    `json:"entry"`
	Sig   b64    `json:"sig"`
}

func (a *api) getRoster(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	from, ok := intParam(r.URL.Query().Get("from"), 0, 0, math.MaxInt64)
	if !ok {
		return errBadRequest
	}
	head, entries, err := a.st.Roster(r.Context(), s.AccountID, uint64(from))
	if err != nil {
		return err
	}
	out := make([]rosterEntry, len(entries))
	for i, e := range entries {
		out[i] = rosterEntry{e.Index, e.Entry, e.Sig}
	}
	return reply(w, http.StatusOK, rosterResponse{out, head})
}

type signedEntry struct {
	Entry b64 `json:"entry"`
	Sig   b64 `json:"sig"`
}

type appendRosterRequest struct {
	Entries []signedEntry `json:"entries"`
	Keys    []wrappedKey  `json:"keys"`
}

func (a *api) postRoster(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	im := r.Header.Get("If-Match")
	if im == "" {
		return errPrecondition
	}
	expect, ok := etag(im)
	var req appendRosterRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok || len(req.Entries) < 1 || len(req.Entries) > maxRosterBatch || len(req.Keys) > maxRosterBatch {
		return errBadRequest
	}
	entries := make([]store.SignedEntry, len(req.Entries))
	for i, e := range req.Entries {
		entries[i] = store.SignedEntry{Entry: e.Entry, Sig: e.Sig}
	}
	keys := make([]store.WrappedKey, len(req.Keys))
	for i, k := range req.Keys {
		if err := sized(k.Blob, maxKeyBlob); err != nil {
			return err
		}
		keys[i] = store.WrappedKey{RecipientID: k.RecipientID, Epoch: k.Epoch, Blob: k.Blob, SignerID: k.SignerID, Sig: k.Sig}
	}
	head, err := a.st.AppendRoster(r.Context(), s.AccountID, expect, entries, keys)
	if errors.Is(err, store.ErrPrecondition) {
		return reply(w, http.StatusPreconditionFailed, staleHeadResponse{"precondition_failed", head})
	}
	if err != nil {
		return err
	}
	// wakes long-polls so a device removed by these entries gets its 401 at once.
	a.notify.wake(string(s.AccountID))
	return reply(w, http.StatusOK, headBody{head})
}
