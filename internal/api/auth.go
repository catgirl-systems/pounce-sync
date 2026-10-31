package api

import (
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"pounce-sync/internal/store"
)

// clientIP is the TCP peer or the configured header, with IPv6 grouped by /64
// so one host cannot rotate addresses; unparsable values share one bucket.
func (a *api) clientIP(r *http.Request) string {
	ip := r.Header.Get(a.cfg.RealIPHeader)
	if a.cfg.RealIPHeader == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "invalid"
	}
	if addr.Is6() && !addr.Is4In6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}
	return addr.Unmap().String()
}

// open wraps unauthenticated endpoints, rate limited per client ip.
func (a *api) open(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return handle(func(w http.ResponseWriter, r *http.Request) error {
		if !a.ipRate.allow(a.clientIP(r), a.cfg.Now()) {
			return errRateLimited
		}
		return h(w, r)
	})
}

func (a *api) session(r *http.Request) (*store.Session, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw, valid := parseB64(tok, 32)
	if !ok || !valid {
		return nil, store.ErrUnauthorized
	}
	h := sha256.Sum256(raw)
	return a.st.Session(r.Context(), h[:], a.cfg.Now())
}

// auth resolves the bearer session on every request; failed attempts count
// against the client ip in their own budget, so a device looping on a stale
// token cannot block logins from its address. accepted ones count against the
// device. a recovery session only reaches handlers registered with recoveryOK.
func (a *api) auth(recoveryOK bool, h func(http.ResponseWriter, *http.Request, *store.Session) error) http.HandlerFunc {
	return handle(func(w http.ResponseWriter, r *http.Request) error {
		s, err := a.session(r)
		switch {
		case errors.Is(err, store.ErrUnauthorized) && !a.authRate.allow(a.clientIP(r), a.cfg.Now()):
			return errRateLimited
		case err != nil:
			return err
		case !a.devRate.allow(string(s.AccountID)+string(s.DeviceID), a.cfg.Now()):
			return errRateLimited
		case s.Recovery && !recoveryOK:
			return errForbidden
		}
		return h(w, r, s)
	})
}

type createAccountRequest struct {
	AccountID b64          `json:"accountID"`
	Invite    b64          `json:"invite"`
	Entry     b64          `json:"entry"`
	Sig       b64          `json:"sig"`
	Keys      []wrappedKey `json:"keys"`
}

func (a *api) createAccount(w http.ResponseWriter, r *http.Request) error {
	if a.cfg.Registration == "closed" {
		return httpError{http.StatusForbidden, "registration_closed"}
	}
	var req createAccountRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if len(req.AccountID) != 16 {
		return errBadRequest
	}
	// any mode other than "open" requires an invite: fail closed.
	var invite []byte
	if a.cfg.Registration != "open" {
		if len(req.Invite) != 32 {
			return errForbidden
		}
		h := sha256.Sum256(req.Invite)
		invite = h[:]
	}
	keys := make([]store.WrappedKey, len(req.Keys))
	for i, k := range req.Keys {
		if err := sized(k.Blob, maxKeyBlob); err != nil {
			return err
		}
		keys[i] = store.WrappedKey{RecipientID: k.RecipientID, Epoch: k.Epoch, Blob: k.Blob, SignerID: k.SignerID, Sig: k.Sig}
	}
	if err := a.st.CreateAccount(r.Context(), req.AccountID, req.Entry, req.Sig, keys, invite, a.cfg.Now()); err != nil {
		return err
	}
	return reply(w, http.StatusCreated, headBody{0})
}

type challengeResponse struct {
	Nonce b64 `json:"nonce"`
}

type challengeRequest struct {
	AccountID b64 `json:"accountID"`
	DeviceID  b64 `json:"deviceID"`
}

func (a *api) challenge(w http.ResponseWriter, r *http.Request) error {
	var req challengeRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if len(req.AccountID) != 16 || len(req.DeviceID) != 16 {
		return errBadRequest
	}
	nonce, err := a.st.Challenge(r.Context(), req.AccountID, req.DeviceID, a.cfg.Now())
	if err != nil {
		return err
	}
	return reply(w, http.StatusOK, challengeResponse{nonce})
}

type loginResponse struct {
	ExpiresIn int `json:"expiresIn"`
	Token     b64 `json:"token"`
}

type loginRequest struct {
	AccountID b64 `json:"accountID"`
	DeviceID  b64 `json:"deviceID"`
	Nonce     b64 `json:"nonce"`
	Sig       b64 `json:"sig"`
}

func (a *api) login(w http.ResponseWriter, r *http.Request) error {
	var req loginRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if len(req.AccountID) != 16 || len(req.DeviceID) != 16 || len(req.Nonce) != 32 {
		return errBadRequest
	}
	token, err := a.st.Login(r.Context(), req.AccountID, req.DeviceID, req.Nonce, req.Sig, a.cfg.Origin, a.cfg.Now())
	if err != nil {
		return err
	}
	return reply(w, http.StatusOK, loginResponse{int(store.SessionTTL.Seconds()), token})
}

type deleteAccountRequest struct {
	Sig b64 `json:"sig"`
}

func (a *api) deleteAccount(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	var req deleteAccountRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if err := a.st.DeleteAccount(r.Context(), s.AccountID, s.DeviceID, req.Sig, a.cfg.Origin); err != nil {
		return err
	}
	a.notify.wake(string(s.AccountID))
	return noContent(w)
}
