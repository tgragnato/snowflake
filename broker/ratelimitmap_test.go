package main

import (
	"testing"
	"time"
)

func TestRateLimitMapStoresProxyPolls(t *testing.T) {
	t.Parallel()

	rlm := NewRateLimitMap()

	for _, name := range []string{"foo", "bar"} {
		notBefore := time.Now().Add(2 * time.Second)
		res, ok := rlm.CheckAndLimit(name, 5*time.Second)
		if !ok {
			t.Errorf("CheckAndLimit(%q) was limited on first poll", name)
		}
		if !res.After(notBefore) {
			t.Errorf("CheckAndLimit(%q) = %v, want a time after %v", name, res, notBefore)
		}
	}
}

// rateLimitLen reports the number of entries in the rate limit map.
//
// rateLimitMapInner requires external synchronization, and NewRateLimitMap
// starts a goroutine that prunes expired entries every 2 seconds, so the read
// has to hold the map's lock.
func rateLimitLen(m *RateLimitMap) int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.inner.Len()
}

// newTestPool returns a pool whose poll interval is short enough to let the
// expiry test wait it out.
func newTestPool() *SnowflakePool {
	pool := NewSnowflakePool()
	pool.pollInterval = time.Second
	return pool
}

func TestSnowflakePoolAddsToRateLimitMap(t *testing.T) {
	t.Parallel()

	pool := newTestPool()

	if got := rateLimitLen(pool.rateLimitMap); got != 0 {
		t.Fatalf("rate limit map length = %d, want 0", got)
	}
	for i, name := range []string{"foo", "bar"} {
		if _, ok := pool.CheckAndLimit(name); !ok {
			t.Errorf("CheckAndLimit(%q) was limited on first poll", name)
		}
		if got, want := rateLimitLen(pool.rateLimitMap), i+1; got != want {
			t.Errorf("rate limit map length = %d, want %d", got, want)
		}
	}
}

func TestSnowflakePoolLimitsEarlyPoll(t *testing.T) {
	t.Parallel()

	pool := newTestPool()

	if _, ok := pool.CheckAndLimit("foo"); !ok {
		t.Fatal("CheckAndLimit was limited on first poll")
	}
	noSoonerThan, ok := pool.CheckAndLimit("foo")
	if ok {
		t.Error("CheckAndLimit was not limited on an immediate second poll")
	}
	if time.Now().After(noSoonerThan) {
		t.Errorf("noSoonerThan = %v, want a time in the future", noSoonerThan)
	}
}

func TestSnowflakePoolAllowsPollAfterLimitExpires(t *testing.T) {
	t.Parallel()

	pool := newTestPool()

	if _, ok := pool.CheckAndLimit("foo"); !ok {
		t.Fatal("CheckAndLimit was limited on first poll")
	}
	<-time.After(pool.pollInterval)
	noSoonerThan, ok := pool.CheckAndLimit("foo")
	if !ok {
		t.Error("CheckAndLimit was still limited after the poll interval elapsed")
	}
	if time.Now().After(noSoonerThan) {
		t.Errorf("noSoonerThan = %v, want a time in the future", noSoonerThan)
	}
}
