package api

import (
	"net/http"
	"strconv"

	"pounce-sync/internal/store"
)

type putKeyRequest struct {
	Blob     b64 `json:"blob"`
	SignerID b64 `json:"signerID"`
	Sig      b64 `json:"sig"`
}

func (a *api) putKey(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	recipient, ok := parseB64(r.PathValue("recipient"), 16)
	epoch, perr := strconv.ParseUint(r.PathValue("epoch"), 10, 32)
	var req putKeyRequest
	if err := decode(w, r, bodyLimit, &req); err != nil {
		return err
	}
	if !ok || perr != nil {
		return errBadRequest
	}
	if err := sized(req.Blob, maxKeyBlob); err != nil {
		return err
	}
	if string(req.SignerID) != string(s.DeviceID) {
		return errForbidden
	}
	k := store.WrappedKey{RecipientID: recipient, Epoch: uint32(epoch), Blob: req.Blob, SignerID: req.SignerID, Sig: req.Sig}
	if err := a.st.PutKey(r.Context(), s.AccountID, k); err != nil {
		return err
	}
	return noContent(w)
}

func (a *api) getKey(w http.ResponseWriter, r *http.Request, s *store.Session) error {
	epoch, err := strconv.ParseUint(r.PathValue("epoch"), 10, 32)
	if err != nil {
		return errBadRequest
	}
	k, err := a.st.GetKey(r.Context(), s.AccountID, s.DeviceID, uint32(epoch))
	if err != nil {
		return err
	}
	return reply(w, http.StatusOK, wrappedKey{k.RecipientID, k.Epoch, k.Blob, k.SignerID, k.Sig})
}
