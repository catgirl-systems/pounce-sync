package api

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"pounce-sync/internal/store"
)

type changesResponse struct {
	Changes   []*record `json:"changes"`
	More      bool      `json:"more"`
	NextSince int64     `json:"nextSince"`
}

type staleRecordResponse struct {
	Current *record `json:"current"`
	Error   string  `json:"error"`
}

// changes answers at once when records follow since; otherwise it waits for a
// notification, the deadline or shutdown, re-checking the session before going on.
func (a *api) changes(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	q := r.URL.Query()
	since, ok1 := intParam(q.Get("since"), 0, 0, math.MaxInt64)
	limit, ok2 := intParam(q.Get("limit"), 500, 1, 1000)
	wait, ok3 := intParam(q.Get("wait"), 0, 0, maxWait)
	if !ok1 || !ok2 || !ok3 {
		return errBadRequest
	}
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	for {
		woken := a.notify.wait(string(s.AccountID))
		if done, err := a.page(w, r, s, since, int(limit), wait == 0); done || err != nil {
			return err
		}
		select {
		case <-woken:
		case <-deadline.C:
			wait = 0
		case <-a.cfg.Stop:
			wait = 0
		case <-r.Context().Done():
			return nil
		}
		if _, err := a.session(r); err != nil {
			return err
		}
	}
}

// page replies with the records after since, unless there are none and force is
// false. it holds a heavy slot only while the page is read and written, not while
// a long-poll waits; it returns whether it replied.
func (a *api) page(w http.ResponseWriter, r *http.Request, s *store.Session, since int64, limit int, force bool) (bool, error) {
	release, err := a.heavy.acquire(string(s.AccountID))
	if err != nil {
		return false, err
	}
	defer release()
	recs, more, err := a.st.Changes(r.Context(), s.AccountID, since, limit)
	if err != nil || (len(recs) == 0 && !force) {
		return false, err
	}
	out := make([]*record, len(recs))
	next := since
	for i := range recs {
		out[i] = toRecord(&recs[i])
		next = int64(recs[i].Seq)
	}
	return true, reply(w, http.StatusOK, changesResponse{out, more, next})
}

type putRecordRequest struct {
	Blob b64 `json:"blob"`
}

func (a *api) putRecord(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	id, ok := parseB64(r.PathValue("id"), 16)
	inm, im := r.Header.Get("If-None-Match"), r.Header.Get("If-Match")
	// create is exactly `If-None-Match: *`, update is a positive `If-Match` revision.
	var expect uint64
	switch {
	case inm == "" && im == "":
		return errPrecondition
	case inm != "":
		ok = ok && inm == "*" && im == ""
	default:
		var good bool
		expect, good = etag(im)
		ok = ok && good && expect > 0
	}
	var req putRecordRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok {
		return errBadRequest
	}
	recs, failed, err := a.st.Batch(r.Context(), s.AccountID, s.DeviceID, []store.Write{{ID: id, IfMatch: expect, Blob: req.Blob}}, a.cfg.MaxRecords)
	if errors.Is(err, store.ErrPrecondition) {
		return reply(w, http.StatusPreconditionFailed, staleRecordResponse{toRecord(failed[0].Current), "precondition_failed"})
	}
	if err != nil {
		return err
	}
	a.notify.wake(string(s.AccountID))
	w.Header().Set("ETag", `"`+strconv.FormatUint(recs[0].Rev, 10)+`"`)
	return reply(w, http.StatusOK, toRecord(&recs[0]))
}

type batchWrite struct {
	ID      b64    `json:"id"`
	IfMatch uint64 `json:"ifMatch"`
	Blob    b64    `json:"blob"`
}

type batchRequest struct {
	Writes []batchWrite `json:"writes"`
}

type batchResponse struct {
	Results []*record `json:"results"`
}

type staleBatchResponse struct {
	Error  string         `json:"error"`
	Failed []batchFailure `json:"failed"`
}

type batchFailure struct {
	ID      b64     `json:"id"`
	Current *record `json:"current"`
}

// batch takes its heavy slot only once the body is read, so a device that stalls
// its uploads cannot hold the account's slots against its siblings.
func (a *api) batch(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	var req batchRequest
	if err := decode(w, r, batchLimit, &req); err != nil {
		return err
	}
	if len(req.Writes) < 1 || len(req.Writes) > maxBatch {
		return errBadRequest
	}
	seen := map[string]bool{}
	ws := make([]store.Write, len(req.Writes))
	for i, wr := range req.Writes {
		if len(wr.ID) != 16 || seen[string(wr.ID)] {
			return errBadRequest
		}
		seen[string(wr.ID)] = true
		ws[i] = store.Write{ID: wr.ID, IfMatch: wr.IfMatch, Blob: wr.Blob}
	}
	release, err := a.heavy.acquire(string(s.AccountID))
	if err != nil {
		return err
	}
	defer release()
	recs, failed, err := a.st.Batch(r.Context(), s.AccountID, s.DeviceID, ws, a.cfg.MaxRecords)
	if errors.Is(err, store.ErrPrecondition) {
		out := make([]batchFailure, len(failed))
		for i, f := range failed {
			out[i] = batchFailure{f.ID, toRecord(f.Current)}
		}
		return reply(w, http.StatusPreconditionFailed, staleBatchResponse{"precondition_failed", out})
	}
	if err != nil {
		return err
	}
	a.notify.wake(string(s.AccountID))
	out := make([]*record, len(recs))
	for i := range recs {
		out[i] = toRecord(&recs[i])
	}
	return reply(w, http.StatusOK, batchResponse{out})
}
