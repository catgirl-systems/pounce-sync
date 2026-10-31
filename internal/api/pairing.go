package api

import (
	"net/http"

	"pounce-sync/internal/store"
)

type createPairingResponse struct {
	ExpiresIn int `json:"expiresIn"`
	PairingID b64 `json:"pairingID"`
}

type createPairingRequest struct {
	AuthTokenHash b64 `json:"authTokenHash"`
}

func (a *api) createPairing(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	var req createPairingRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if len(req.AuthTokenHash) != 32 {
		return errBadRequest
	}
	id, err := a.st.CreatePairing(r.Context(), s.AccountID, s.DeviceID, req.AuthTokenHash, a.cfg.Now())
	if err != nil {
		return err
	}
	return reply(w, http.StatusCreated, createPairingResponse{int(store.PairingTTL.Seconds()), id})
}

type joinPairingRequest struct {
	AuthToken b64 `json:"authToken"`
	Payload   b64 `json:"payload"`
}

func (a *api) joinPairing(w http.ResponseWriter, r *http.Request) error {
	id, ok := parseB64(r.PathValue("id"), 16)
	var req joinPairingRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok || len(req.AuthToken) != 32 {
		return errBadRequest
	}
	if err := sized(req.Payload, maxPayload); err != nil {
		return err
	}
	if err := a.st.JoinPairing(r.Context(), id, req.AuthToken, req.Payload, a.cfg.Now()); err != nil {
		return err
	}
	return noContent(w)
}

type pairingPayloadResponse struct {
	Payload b64 `json:"payload"`
}

func (a *api) pairingPayload(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	id, ok := parseB64(r.PathValue("id"), 16)
	if !ok {
		return errBadRequest
	}
	payload, err := a.st.PairingPayload(r.Context(), s.AccountID, id, a.cfg.Now())
	if err != nil {
		return err
	}
	if payload == nil {
		return noContent(w)
	}
	return reply(w, http.StatusOK, pairingPayloadResponse{payload})
}

type pairingNonceRequest struct {
	Nonce b64 `json:"nonce"`
	Sig   b64 `json:"sig"`
}

func (a *api) pairingNonce(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	id, ok := parseB64(r.PathValue("id"), 16)
	var req pairingNonceRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok || len(req.Nonce) != 32 || len(req.Sig) != 64 {
		return errBadRequest
	}
	if err := a.st.SetPairingNonce(r.Context(), s.AccountID, s.DeviceID, id, req.Nonce, req.Sig, a.cfg.Now()); err != nil {
		return err
	}
	return noContent(w)
}

type pollPairingResponse struct {
	Nonce    b64 `json:"nonce"`
	Sig      b64 `json:"sig"`
	SignerID b64 `json:"signerID"`
}

type pollPairingRequest struct {
	AuthToken b64 `json:"authToken"`
}

func (a *api) pollPairing(w http.ResponseWriter, r *http.Request) error {
	id, ok := parseB64(r.PathValue("id"), 16)
	var req pollPairingRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok || len(req.AuthToken) != 32 {
		return errBadRequest
	}
	n, err := a.st.PollPairing(r.Context(), id, req.AuthToken, a.cfg.Now())
	if err != nil {
		return err
	}
	if n == nil {
		return noContent(w)
	}
	return reply(w, http.StatusOK, pollPairingResponse{n.Nonce, n.Sig, n.SignerID})
}
