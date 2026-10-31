package api

import (
	"net/http"
	"time"

	"pounce-sync/internal/store"
)

type Config struct {
	Origin       string
	Registration string // open|invite|closed
	MaxRecords   int
	RateIP       int
	RateDevice   int
	RealIPHeader string
	Now          func() time.Time // nil means time.Now
	Stop         <-chan struct{}  // closed on shutdown to end long-polls; nil never closes
}

const (
	bodyLimit  = 256 << 10
	batchLimit = 4 << 20
	maxBatch   = 32
	maxPayload = 4 << 10
	maxKeyBlob = 1 << 10
	maxWait    = 30
	heavySlots = 4
)

type api struct {
	cfg      Config
	st       *store.Store
	ipRate   *limiter // unauthenticated endpoints, per client ip
	authRate *limiter // failed bearer authentications, per client ip
	devRate  *limiter
	notify   *notifier
	heavy    *slots
}

func New(cfg Config, st *store.Store) http.Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &api{cfg: cfg, st: st, ipRate: newLimiter(cfg.RateIP), authRate: newLimiter(cfg.RateIP), devRate: newLimiter(cfg.RateDevice), notify: newNotifier(), heavy: newSlots(heavySlots)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/accounts", a.open(a.createAccount))
	mux.HandleFunc("POST /v1/auth/challenge", a.open(a.challenge))
	mux.HandleFunc("POST /v1/auth/session", a.open(a.login))
	mux.HandleFunc("GET /v1/roster", a.auth(true, a.getRoster))
	mux.HandleFunc("POST /v1/roster", a.auth(true, a.postRoster))
	mux.HandleFunc("PUT /v1/keys/{recipient}/{epoch}", a.auth(false, a.putKey))
	mux.HandleFunc("GET /v1/keys/{epoch}", a.auth(true, a.getKey))
	mux.HandleFunc("GET /v1/changes", a.auth(false, a.changes))
	mux.HandleFunc("PUT /v1/records/{id}", a.auth(false, a.putRecord))
	mux.HandleFunc("POST /v1/batch", a.auth(false, a.batch))
	mux.HandleFunc("POST /v1/pairing", a.auth(false, a.createPairing))
	mux.HandleFunc("POST /v1/pairing/{id}/join", a.open(a.joinPairing))
	mux.HandleFunc("GET /v1/pairing/{id}", a.auth(false, a.pairingPayload))
	mux.HandleFunc("POST /v1/pairing/{id}/nonce", a.auth(false, a.pairingNonce))
	mux.HandleFunc("POST /v1/pairing/{id}/poll", a.open(a.pollPairing))
	mux.HandleFunc("DELETE /v1/account", a.auth(false, a.deleteAccount))
	mux.HandleFunc("/", handle(func(http.ResponseWriter, *http.Request) error { return store.ErrNotFound }))
	return mux
}
