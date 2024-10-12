package timecache

import (
	"context"
	"sync"
	"time"
)

var backgroundSweepInterval = time.Minute

func background(ctx context.Context, lk sync.Locker, m map[string]time.Time) {
	ticker := time.NewTicker(backgroundSweepInterval)

	for {
		select {
		case now := <-ticker.C:
			sweep(lk, m, now)

		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func sweep(lk sync.Locker, m map[string]time.Time, now time.Time) {
	lk.Lock()

	for k, expiry := range m {
		if expiry.Before(now) {
			delete(m, k)
		}
	}

	lk.Unlock()
}
