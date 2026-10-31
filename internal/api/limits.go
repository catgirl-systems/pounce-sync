package api

import (
	"sync"
	"time"
)

// limiter counts requests per key in fixed one-minute windows; the whole map
// is dropped when the minute changes, so memory never outlives a window.
type limiter struct {
	mu     sync.Mutex
	limit  int
	window int64
	counts map[string]int
}

func newLimiter(limit int) *limiter {
	return &limiter{limit: limit, counts: map[string]int{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if m := now.Unix() / 60; m != l.window {
		l.window = m
		l.counts = map[string]int{}
	}
	l.counts[key]++
	return l.counts[key] <= l.limit
}

// notifier wakes long-polls: wait returns a channel that is closed by the next
// wake for the same account. callers take it before querying so no write is missed.
type notifier struct {
	mu sync.Mutex
	ch map[string]chan struct{}
}

func newNotifier() *notifier { return &notifier{ch: map[string]chan struct{}{}} }

func (n *notifier) wait(account string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.ch[account]
	if !ok {
		c = make(chan struct{})
		n.ch[account] = c
	}
	return c
}

func (n *notifier) wake(account string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.ch[account]; ok {
		close(c)
		delete(n.ch, account)
	}
}

// slots caps concurrent heavy requests (change pages, batches) per account, so
// clients that never read their responses cannot pin unbounded memory.
type slots struct {
	mu    sync.Mutex
	limit int
	n     map[string]int
}

func newSlots(limit int) *slots { return &slots{limit: limit, n: map[string]int{}} }

// acquire returns the release func, or errRateLimited when the key is at its limit.
func (s *slots) acquire(key string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n[key] >= s.limit {
		return nil, errRateLimited
	}
	s.n[key]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.n[key]--; s.n[key] == 0 {
			delete(s.n, key)
		}
	}, nil
}
