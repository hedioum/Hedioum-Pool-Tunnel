package pool

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// fakeDialer pairs a yamux client/server over an in-memory pipe and drains any
// streams the pool opens, standing in for a real egress.
func fakeDialer() (*yamux.Session, error) {
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
	return yamux.Client(c, yamux.DefaultConfig())
}

func TestSubPoolsTCPandUDP(t *testing.T) {
	hm := NewHubManager()
	cfg := config.ForeignNode{
		Alias:               "n1",
		TargetIP:            "1.2.3.4",
		MinConnections:      1,
		MaxConnections:      3,
		BandwidthLimitMbps:  50,
		BandwidthJitterMbps: 5,
	}
	hm.RegisterNode(cfg, fakeDialer)

	// Warm-up: TCP min (1) + UDP min (udpMinConns=2) = 3 physical connections.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if hm.GetStats("n1").ActiveConns >= 1+udpMinConns {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pools did not warm up: %+v", hm.GetStats("n1"))
		}
		time.Sleep(100 * time.Millisecond)
	}

	tcpStream, err := hm.GetStreamTCP("n1")
	if err != nil {
		t.Fatalf("GetStreamTCP: %v", err)
	}
	defer tcpStream.Close()

	udpStream, err := hm.GetStreamUDP("n1")
	if err != nil {
		t.Fatalf("GetStreamUDP: %v", err)
	}
	defer udpStream.Close()

	if _, err := hm.GetStreamTCP("unknown"); err == nil {
		t.Fatal("expected an error for an unknown node")
	}
}
