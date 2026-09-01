package snowflake_client

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"tgragnato.it/snowflake/common/event"
)

type FakeDialer struct {
	max int
}

func (w FakeDialer) Catch() (*WebRTCPeer, error) {
	fmt.Println("Caught a dummy snowflake.")
	return &WebRTCPeer{closed: make(chan struct{})}, nil
}

func (w FakeDialer) GetMax() int {
	return w.max
}

type FakeSocksConn struct {
	net.Conn
	rejected bool
}

func (f *FakeSocksConn) Reject() error {
	f.rejected = true
	return nil
}
func (f *FakeSocksConn) Grant(addr *net.TCPAddr) error { return nil }

// newTestPeers builds a Peers backed by a FakeDialer with the given capacity.
func newTestPeers(t *testing.T, max int) *Peers {
	t.Helper()
	p, err := NewPeers(FakeDialer{max: max})
	if err != nil {
		t.Fatalf("NewPeers: %v", err)
	}
	return p
}

func TestPeersConstruction(t *testing.T) {
	t.Parallel()

	p := newTestPeers(t, 1)
	if got := p.Tongue.GetMax(); got != 1 {
		t.Errorf("GetMax() = %d, want 1", got)
	}
	if p.snowflakeChan == nil {
		t.Fatal("snowflakeChan is nil")
	}
	if got := cap(p.snowflakeChan); got != 1 {
		t.Errorf("cap(snowflakeChan) = %d, want 1", got)
	}
}

func TestPeersRequireTongue(t *testing.T) {
	t.Parallel()

	if _, err := NewPeers(nil); err == nil {
		t.Fatal("NewPeers(nil) succeeded, want error")
	}

	// Set the dialer so that collection is possible.
	p := newTestPeers(t, 1)
	if _, err := p.Collect(); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := p.Count(); got != 1 {
		t.Errorf("Count() = %d, want 1", got)
	}
}

func TestPeersCollectUntilCapacity(t *testing.T) {
	t.Parallel()

	const c = 5
	p := newTestPeers(t, c)

	// Fill up to capacity.
	for i := range c {
		if _, err := p.Collect(); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
		if got := p.Count(); got != i+1 {
			t.Errorf("Count() = %d, want %d", got, i+1)
		}
	}

	// But adding another gives an error.
	if _, err := p.Collect(); err == nil {
		t.Error("Collect beyond capacity succeeded, want error")
	}
	if got := p.Count(); got != c {
		t.Errorf("Count() = %d, want %d", got, c)
	}

	// But popping allows it to continue.
	s := p.Pop()
	if s == nil {
		t.Fatal("Pop() = nil")
	}
	s.Close()
	if got := p.Count(); got != c-1 {
		t.Errorf("Count() = %d, want %d", got, c-1)
	}

	if _, err := p.Collect(); err != nil {
		t.Fatalf("Collect after Pop: %v", err)
	}
	if got := p.Count(); got != c {
		t.Errorf("Count() = %d, want %d", got, c)
	}
}

func TestPeersCountPurgesClosedPeers(t *testing.T) {
	t.Parallel()

	p := newTestPeers(t, 5)
	for i := range 4 {
		if _, err := p.Collect(); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if got := p.Count(); got != 4 {
		t.Fatalf("Count() = %d, want 4", got)
	}

	// Count is what purges peers marked for deletion.
	for want := 3; want >= 2; want-- {
		p.Pop().Close()
		if got := p.Count(); got != want {
			t.Errorf("Count() = %d, want %d", got, want)
		}
	}
}

func TestPeersEndClosesAllPeers(t *testing.T) {
	t.Parallel()

	const cnt = 5
	p := newTestPeers(t, cnt)
	for range cnt {
		p.activePeers.PushBack(&WebRTCPeer{closed: make(chan struct{})})
	}
	if got := p.Count(); got != cnt {
		t.Fatalf("Count() = %d, want %d", got, cnt)
	}

	p.End()
	<-p.Melted()
	if got := p.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0 after End()", got)
	}
}

func TestPeersPopSkipsClosedPeers(t *testing.T) {
	t.Parallel()

	p := newTestPeers(t, 4)
	wc1, err := p.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wc2, err := p.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wc3, err := p.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if wc1 == nil || wc2 == nil || wc3 == nil {
		t.Fatal("Collect returned a nil peer")
	}

	wc1.Close()
	if got := p.Pop(); got != wc2 {
		t.Errorf("Pop() = %v, want the first peer that is still open", got)
	}
	if got := p.Count(); got != 2 {
		t.Errorf("Count() = %d, want 2", got)
	}

	wc4, err := p.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wc2.Close()
	wc3.Close()
	if got := p.Pop(); got != wc4 {
		t.Errorf("Pop() = %v, want the only remaining open peer", got)
	}
}

func TestPeersTerminateConnectLoop(t *testing.T) {
	t.Parallel()

	p := newTestPeers(t, 4)
	go func() {
		for {
			p.Collect()
			select {
			case <-p.Melted():
				return
			default:
			}
		}
	}()
	<-time.After(10 * time.Second)

	p.End()
	<-p.Melted()
	if got := p.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0 after End()", got)
	}
}

func TestWebRTCDialerConstruction(t *testing.T) {
	t.Parallel()

	broker := &BrokerChannel{}
	d := NewWebRTCDialer(broker, nil, 1)
	if d == nil {
		t.Fatal("NewWebRTCDialer returned nil")
	}
	if d.BrokerChannel == nil {
		t.Error("BrokerChannel is nil")
	}
}

func TestWebRTCDialerCatch(t *testing.T) {
	t.Skip("disabled: Catch against an empty BrokerChannel blocks")

	broker := &BrokerChannel{}
	d := NewWebRTCDialer(broker, nil, 1)
	conn, err := d.Catch()
	if conn != nil {
		t.Errorf("Catch() = %v, want nil", conn)
	}
	if err == nil {
		t.Error("Catch() succeeded, want error")
	}
}

func TestWebRTCPeerStaleness(t *testing.T) {
	t.Parallel()

	p := &WebRTCPeer{
		closed:       make(chan struct{}),
		eventsLogger: event.NewSnowflakeEventDispatcher(),
	}
	go p.checkForStaleness(time.Second)
	<-time.After(2 * time.Second)
	if !p.Closed() {
		t.Error("peer was not closed after the staleness timeout elapsed")
	}
}

func TestICEServerParser(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input  []string
		urls   [][]string
		length int
	}{
		{
			[]string{"stun:stun.l.google.com:19302", "stun:stun.ekiga.net"},
			[][]string{{"stun:stun.l.google.com:19302"}, {"stun:stun.ekiga.net:3478"}},
			2,
		},
		{
			// Only well-formed stun: URLs are kept; the rest are dropped.
			[]string{"stun:stun1.l.google.com:19302", "stun.ekiga.net", "stun:stun.example.com:1234/path?query",
				"https://example.com", "turn:relay.metered.ca:80?transport=udp"},
			[][]string{{"stun:stun1.l.google.com:19302"}},
			1,
		},
	} {
		servers := parseIceServers(test.input)

		if test.urls == nil && servers != nil {
			t.Errorf("parseIceServers(%v) = %v, want nil", test.input, servers)
		}
		if test.urls != nil && servers == nil {
			t.Errorf("parseIceServers(%v) = nil, want non-nil", test.input)
		}
		if got := len(servers); got != test.length {
			t.Errorf("parseIceServers(%v) returned %d servers, want %d", test.input, got, test.length)
		}
		for _, server := range servers {
			if !slices.ContainsFunc(test.urls, func(urls []string) bool {
				return slices.Equal(urls, server.URLs)
			}) {
				t.Errorf("parseIceServers(%v) returned unexpected URLs %v", test.input, server.URLs)
			}
		}
	}
}
