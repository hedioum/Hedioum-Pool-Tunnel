package pool

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// reversePipe returns the hub's yamux CLIENT session over an in-memory pipe whose far
// end is a yamux server draining every stream (a stand-in for the dialing foreign).
func reversePipe(t *testing.T) *yamux.Session {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		srv, err := yamux.Server(s, yamux.DefaultConfig())
		if err != nil {
			s.Close()
			return
		}
		for {
			st, err := srv.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, st)
		}
	}()
	sess, err := yamux.Client(c, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func reverseTestNode(alias string, min, max int) config.ForeignNode {
	return config.ForeignNode{
		Alias:               alias,
		AuthToken:           "0123456789abcdef0123456789abcdef",
		Reverse:             true,
		MinConnections:      min,
		MaxConnections:      max,
		BandwidthLimitMbps:  50,
		BandwidthJitterMbps: 5,
	}
}

// TestReversePoolNeverDials: a reverse node has no dialer, so the pools stay empty
// until pipes are adopted (no warm-up dialing, no panic on a nil dialer).
func TestReversePoolNeverDials(t *testing.T) {
	hm := NewHubManager()
	hm.RegisterReverseNode(reverseTestNode("r0", 2, 4))

	time.Sleep(1500 * time.Millisecond) // longer than the staggered warm-up would take
	if st := hm.GetStats("r0"); st.ActiveConns != 0 {
		t.Fatalf("reverse pool must not dial: %+v", st)
	}
	if _, err := hm.GetStreamTCP("r0"); err == nil {
		t.Fatal("expected no stream while no pipe has been adopted")
	}
}

// TestAdoptFillsUDPThenTCP: the first udpMinConns adopted pipes feed the UDP
// sub-pool, the rest the TCP sub-pool, and both serve streams.
func TestAdoptFillsUDPThenTCP(t *testing.T) {
	hm := NewHubManager()
	hm.RegisterReverseNode(reverseTestNode("r1", 2, 4))

	if _, err := hm.GetStreamUDP("r1"); err == nil {
		t.Fatal("UDP sub-pool must be empty before adoption")
	}
	for i := 0; i < udpMinConns; i++ {
		if err := hm.AdoptSession("r1", reversePipe(t), "tls"); err != nil {
			t.Fatalf("adopt %d: %v", i, err)
		}
	}
	if _, err := hm.GetStreamTCP("r1"); err == nil {
		t.Fatal("TCP sub-pool must still be empty: the first pipes belong to UDP")
	}
	us, err := hm.GetStreamUDP("r1")
	if err != nil {
		t.Fatalf("UDP sub-pool should serve after adoption: %v", err)
	}
	us.Close()

	if err := hm.AdoptSession("r1", reversePipe(t), "tls"); err != nil {
		t.Fatalf("adopt TCP pipe: %v", err)
	}
	ts, err := hm.GetStreamTCP("r1")
	if err != nil {
		t.Fatalf("TCP sub-pool should serve after adoption: %v", err)
	}
	ts.Close()
}

// TestAdoptRespectsMaxConnections: a node never holds more active TCP pipes than
// max_connections; extra pipes are rejected (the caller closes them).
func TestAdoptRespectsMaxConnections(t *testing.T) {
	hm := NewHubManager()
	hm.RegisterReverseNode(reverseTestNode("r2", 1, 2))

	for i := 0; i < udpMinConns; i++ { // consume the UDP slots
		if err := hm.AdoptSession("r2", reversePipe(t), "tls"); err != nil {
			t.Fatal(err)
		}
	}
	// maxConnections = max(2, min+5 only if max<min) = 2 for the TCP sub-pool.
	for i := 0; i < 2; i++ {
		if err := hm.AdoptSession("r2", reversePipe(t), "tls"); err != nil {
			t.Fatalf("adopt %d within the cap: %v", i, err)
		}
	}
	extra := reversePipe(t)
	defer extra.Close()
	if err := hm.AdoptSession("r2", extra, "tls"); err == nil {
		t.Fatal("a pipe above max_connections must be rejected")
	}
}

func TestAdoptUnknownNode(t *testing.T) {
	hm := NewHubManager()
	s := reversePipe(t)
	defer s.Close()
	if err := hm.AdoptSession("nope", s, "tls"); err == nil {
		t.Fatal("adopting into an unknown node must fail")
	}
}

// TestMixedForwardAndReverseNodes: one hub can run normal (hub-dials) nodes next to a
// reverse node. The forward node keeps dialing and serving; the reverse node stays
// empty until its foreign dials in, and adopting its pipes never touches the other.
func TestMixedForwardAndReverseNodes(t *testing.T) {
	hm := NewHubManager()

	fwd := reverseTestNode("fwd", 1, 3)
	fwd.Reverse = false
	hm.RegisterNode(fwd, fakeDialer)                     // normal node: the hub dials
	hm.RegisterReverseNode(reverseTestNode("rev", 1, 3)) // reverse node: the foreign dials

	// The forward node warms up on its own (TCP min 1 + UDP min 2).
	deadline := time.Now().Add(10 * time.Second)
	for hm.GetStats("fwd").ActiveConns < 1+udpMinConns {
		if time.Now().After(deadline) {
			t.Fatalf("forward node did not warm up next to a reverse node: %+v", hm.GetStats("fwd"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The reverse node dialed nothing.
	if st := hm.GetStats("rev"); st.ActiveConns != 0 {
		t.Fatalf("reverse node must stay empty until its foreign dials in: %+v", st)
	}

	// Adopt the reverse node's pipes: it serves, and the forward node is unaffected.
	before := hm.GetStats("fwd").ActiveConns
	for i := 0; i < udpMinConns+1; i++ {
		if err := hm.AdoptSession("rev", reversePipe(t), "tls"); err != nil {
			t.Fatal(err)
		}
	}
	for _, alias := range []string{"fwd", "rev"} {
		s, err := hm.GetStreamTCP(alias)
		if err != nil {
			t.Fatalf("node %q must serve streams: %v", alias, err)
		}
		s.Close()
	}
	if after := hm.GetStats("fwd").ActiveConns; after != before {
		t.Fatalf("adopting reverse pipes changed the forward node: %d -> %d", before, after)
	}
}
