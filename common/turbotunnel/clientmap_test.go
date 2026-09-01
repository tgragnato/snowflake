package turbotunnel

import (
	"net"
	"testing"
	"time"
)

func newTestInner() *clientMapInner {
	return &clientMapInner{
		byAge:  make([]*clientRecord, 0),
		byAddr: make(map[net.Addr]int),
	}
}

// The same client must always get the same send queue, otherwise packets
// queued for it would be split across queues and partly never delivered.
func TestClientMapSendQueueIsStablePerClient(t *testing.T) {
	t.Parallel()

	m := NewClientMap(time.Hour)
	id := NewClientID()

	first := m.SendQueue(id)
	if second := m.SendQueue(id); second != first {
		t.Error("the same client got two different send queues")
	}

	if other := m.SendQueue(NewClientID()); other == first {
		t.Error("two different clients share a send queue")
	}
}

func TestClientMapInnerRemoveExpired(t *testing.T) {
	t.Parallel()

	inner := newTestInner()
	start := time.Now()
	timeout := time.Minute

	old := NewClientID()
	recent := NewClientID()
	oldQueue := inner.SendQueue(old, start)
	inner.SendQueue(recent, start.Add(30*time.Second))

	if got := inner.Len(); got != 2 {
		t.Fatalf("expected 2 records, got %d", got)
	}

	// At start+timeout only the older record has been idle long enough.
	inner.removeExpired(start.Add(timeout), timeout)

	if got := inner.Len(); got != 1 {
		t.Fatalf("expected 1 record to survive, got %d", got)
	}
	if _, ok := inner.byAddr[old]; ok {
		t.Error("the expired client is still in the map")
	}
	if _, ok := inner.byAddr[recent]; !ok {
		t.Error("the recent client was expired too early")
	}

	// Expiring a client closes its send queue, so a sender can tell that
	// the session is gone instead of blocking on it forever.
	if _, open := <-oldQueue; open {
		t.Error("the expired client's send queue was not closed")
	}
}

// Records must expire oldest-first: the heap ordering is what makes the sweep
// cheap, and a wrong order would drop live sessions.
func TestClientMapInnerRemoveExpiredInAgeOrder(t *testing.T) {
	t.Parallel()

	inner := newTestInner()
	start := time.Now()
	timeout := time.Minute

	// Insert out of chronological order to make sure the heap, not the
	// insertion order, decides who goes first.
	ids := make([]ClientID, 4)
	for i := range ids {
		ids[i] = NewClientID()
	}
	inner.SendQueue(ids[2], start.Add(2*time.Minute))
	inner.SendQueue(ids[0], start)
	inner.SendQueue(ids[3], start.Add(3*time.Minute))
	inner.SendQueue(ids[1], start.Add(time.Minute))

	// Expire everything last seen at or before start+1m.
	inner.removeExpired(start.Add(2*time.Minute), timeout)

	for i, id := range ids {
		_, present := inner.byAddr[id]
		wantPresent := i >= 2
		if present != wantPresent {
			t.Errorf("record %d (last seen +%dm): present = %v, want %v", i, i, present, wantPresent)
		}
	}
}

// Traffic from a client refreshes it, so an active session is never expired.
func TestClientMapInnerSendQueueRefreshesLastSeen(t *testing.T) {
	t.Parallel()

	inner := newTestInner()
	start := time.Now()
	timeout := time.Minute

	id := NewClientID()
	queue := inner.SendQueue(id, start)

	// Seen again just before the timeout would have elapsed.
	if refreshed := inner.SendQueue(id, start.Add(59*time.Second)); refreshed != queue {
		t.Error("refreshing a client replaced its send queue")
	}

	inner.removeExpired(start.Add(timeout), timeout)

	if _, ok := inner.byAddr[id]; !ok {
		t.Error("a client that was seen again was still expired")
	}
}

func TestClientMapInnerRemoveExpiredOnEmptyMap(t *testing.T) {
	t.Parallel()

	inner := newTestInner()

	// Must not panic or underflow with nothing to expire.
	inner.removeExpired(time.Now(), time.Minute)

	if got := inner.Len(); got != 0 {
		t.Errorf("expected an empty map, got %d records", got)
	}
}

func TestClientMapInnerRemoveExpiredEverything(t *testing.T) {
	t.Parallel()

	inner := newTestInner()
	start := time.Now()

	for range 5 {
		inner.SendQueue(NewClientID(), start)
	}

	inner.removeExpired(start.Add(time.Hour), time.Minute)

	if got := inner.Len(); got != 0 {
		t.Errorf("expected every record to be expired, got %d left", got)
	}
}

// Benchmark the ClientMap.SendQueue function. This is mainly measuring the cost
// of the mutex operations around the call to clientMapInner.SendQueue.
func BenchmarkSendQueue(b *testing.B) {
	m := NewClientMap(1 * time.Hour)
	id := NewClientID()
	m.SendQueue(id) // populate the entry for id

	for b.Loop() {
		m.SendQueue(id)
	}
}
