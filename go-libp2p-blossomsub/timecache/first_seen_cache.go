package timecache

import (
	"context"
	"sync"
	"time"
)

// FirstSeenCache is a time cache that only marks the expiry of a message when first added.
type FirstSeenCache struct {
	lk  sync.RWMutex
	m   map[string]time.Time
	ttl time.Duration

	done func()
}

var _ TimeCache = (*FirstSeenCache)(nil)

func newFirstSeenCache(ttl time.Duration) *FirstSeenCache {
	tc := &FirstSeenCache{
		m:   make(map[string]time.Time),
		ttl: ttl,
	}

	ctx, done := context.WithCancel(context.Background())
	tc.done = done
	go background(ctx, &tc.lk, tc.m)

	return tc
}

func (tc *FirstSeenCache) Done() {
	tc.done()
}

func (tc *FirstSeenCache) Has(s string) bool {
	tc.lk.RLock()

	_, ok := tc.m[s]
	tc.lk.RUnlock()
	return ok
}

func (tc *FirstSeenCache) Add(s string) bool {
	tc.lk.Lock()

	_, ok := tc.m[s]
	if ok {
		tc.lk.Unlock()
		return false
	}

	tc.m[s] = time.Now().Add(tc.ttl)
	tc.lk.Unlock()
	return true
}
