package egress

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// pipeWithStreams returns a foreign-side (server) yamux session registered in d, with
// n streams the hub side has opened and the foreign has accepted.
func pipeWithStreams(t *testing.T, d *reverseDialer, n int) {
	t.Helper()
	a, b := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = nopWriter{}
	srv, err := yamux.Server(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := yamux.Client(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close(); cli.Close() })
	go func() {
		for {
			if _, err := srv.AcceptStream(); err != nil {
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		if _, err := cli.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for srv.NumStreams() < n {
		if time.Now().After(deadline) {
			t.Fatalf("foreign side saw %d of %d streams", srv.NumStreams(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.mu.Lock()
	d.sessions = append(d.sessions, &reversePipe{sess: srv, target: "x:1", started: time.Now().Add(-time.Minute)})
	d.mu.Unlock()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func newTestDialer(min, max int) *reverseDialer {
	return &reverseDialer{name: "t", min: min, max: max, want: min, health: map[string]*reverseHealth{},
		targets: []config.Endpoint{{Target: "x:1", Mimic: "tls"}}}
}

func TestRescaleFixedRangeNeverMoves(t *testing.T) {
	d := newTestDialer(2, 2)
	pipeWithStreams(t, d, 50)
	pipeWithStreams(t, d, 50)
	d.rescale(2)
	if d.currentWant() != 2 {
		t.Fatalf("min==max must stay fixed, want=%d", d.currentWant())
	}
}

func TestRescaleUpUnderLoadStepsOneAtATimeToMax(t *testing.T) {
	d := newTestDialer(2, 4)
	pipeWithStreams(t, d, reverseScaleUpStreams)
	pipeWithStreams(t, d, reverseScaleUpStreams)
	d.rescale(2)
	if d.currentWant() != 3 {
		t.Fatalf("busy pipes must add one pipe, want=%d", d.currentWant())
	}
	// A second tick right away must not add another (rate limited), and a pipe that is
	// not up yet (live < want) holds the target.
	d.rescale(2)
	if d.currentWant() != 3 {
		t.Fatalf("scale-up must be rate limited, want=%d", d.currentWant())
	}
	d.mu.Lock()
	d.lastUp = time.Now().Add(-time.Minute)
	d.mu.Unlock()
	pipeWithStreams(t, d, reverseScaleUpStreams)
	d.rescale(3)
	if d.currentWant() != 4 {
		t.Fatalf("expected 4, got %d", d.currentWant())
	}
	d.mu.Lock()
	d.lastUp = time.Now().Add(-time.Minute)
	d.mu.Unlock()
	pipeWithStreams(t, d, reverseScaleUpStreams)
	d.rescale(4)
	if d.currentWant() != 4 {
		t.Fatalf("must stop at max, got %d", d.currentWant())
	}
}

func TestRescaleDownWhenIdleKeepsMin(t *testing.T) {
	d := newTestDialer(1, 3)
	d.want = 3
	for i := 0; i < 3; i++ {
		pipeWithStreams(t, d, 0)
	}
	d.rescale(3) // starts the idle clock
	if d.currentWant() != 3 {
		t.Fatalf("must not shrink before the idle time, want=%d", d.currentWant())
	}
	d.mu.Lock()
	d.idleSince = time.Now().Add(-2 * reverseIdleShrink)
	d.mu.Unlock()
	d.rescale(3)
	if d.currentWant() != 2 || d.liveCount() != 2 {
		t.Fatalf("one idle pipe should close: want=%d live=%d", d.currentWant(), d.liveCount())
	}
	d.mu.Lock()
	d.idleSince = time.Now().Add(-2 * reverseIdleShrink)
	d.mu.Unlock()
	d.rescale(2)
	d.mu.Lock()
	d.idleSince = time.Now().Add(-2 * reverseIdleShrink)
	d.mu.Unlock()
	d.rescale(1)
	if d.currentWant() != 1 {
		t.Fatalf("must not shrink below min, want=%d", d.currentWant())
	}
}

// A pipe the hub drops right after the handshake counts as a failure of that endpoint.
func TestEarlyClosedPipeCoolsTheEndpointDown(t *testing.T) {
	d := newTestDialer(1, 1)
	for i := 0; i < reverseFailLimit; i++ {
		a, b := net.Pipe()
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = nopWriter{}
		srv, _ := yamux.Server(a, cfg)
		b.Close()
		srv.Close()
		d.mu.Lock()
		d.sessions = append(d.sessions, &reversePipe{sess: srv, target: "x:1", started: time.Now()})
		d.mu.Unlock()
		d.liveCount()
	}
	d.mu.Lock()
	h := d.health["x:1"]
	cooling := h != nil && h.cooldownUntil.After(time.Now())
	d.mu.Unlock()
	if !cooling {
		t.Fatal("an endpoint whose pipes are dropped at once must cool down")
	}
}
