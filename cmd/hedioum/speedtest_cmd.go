package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	mrand "math/rand/v2"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

// cmdSpeedtest measures raw tunnel throughput to a foreign node, bypassing the
// shaper. It opens its own connection (a mini-hub), independent of the daemon.
func cmdSpeedtest(args []string) {
	fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
	nodeAlias := fs.String("node", "", "node alias (default: first)")
	mimicSel := fs.String("mimic", "", "endpoint mimic to test (default: first)")
	seconds := fs.Int("seconds", 10, "test duration per direction")
	dir := fs.String("dir", "both", "down|up|both")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil {
		fail("no config: %v", err)
	}
	if cfg.Role != "iran" || len(cfg.ForeignNodes) == 0 {
		fail("speedtest runs on the Iran hub with at least one node")
	}
	node := cfg.ForeignNodes[0]
	if *nodeAlias != "" {
		found := false
		for _, n := range cfg.ForeignNodes {
			if n.Alias == *nodeAlias {
				node, found = n, true
				break
			}
		}
		if !found {
			fail("node %q not found", *nodeAlias)
		}
	}
	if node.Reverse {
		fail("speedtest opens its own connection to the foreign, which does not apply to reverse node %q (the foreign dials in)", node.Alias)
	}
	ep := node.Endpoints[0]
	if *mimicSel != "" {
		found := false
		for _, e := range node.Endpoints {
			if e.Mimic == *mimicSel {
				ep, found = e, true
				break
			}
		}
		if !found {
			fail("node %q has no %q endpoint", node.Alias, *mimicSel)
		}
	}

	fmt.Printf("Speedtest to %q via %s@%s (%ds/direction)...\n", node.Alias, ep.Mimic, ep.Target, *seconds)
	if *dir == "down" || *dir == "both" {
		mbps, err := runSpeedtest(ep, node.AuthToken, tunproto.SpeedDown, *seconds)
		report("download", mbps, err)
	}
	if *dir == "up" || *dir == "both" {
		mbps, err := runSpeedtest(ep, node.AuthToken, tunproto.SpeedUp, *seconds)
		report("upload", mbps, err)
	}
}

func report(label string, mbps float64, err error) {
	if err != nil {
		fmt.Printf("  %-8s FAILED: %v\n", label, err)
		return
	}
	fmt.Printf("  %-8s %.1f Mbps\n", label, mbps)
}

func runSpeedtest(ep config.Endpoint, token string, direction byte, seconds int) (float64, error) {
	yc := yamux.DefaultConfig()
	yc.MaxStreamWindowSize = 16 << 20
	sess, err := ingress.DialEndpoint(ep, token, yc)
	if err != nil {
		return 0, err
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer stream.Close()
	if err := tunproto.WriteSpeedtestHeader(stream, direction, uint16(seconds)); err != nil {
		return 0, err
	}

	buf := make([]byte, 64*1024)
	var total int64
	start := time.Now()
	switch direction {
	case tunproto.SpeedDown:
		_ = stream.SetReadDeadline(time.Now().Add(time.Duration(seconds+5) * time.Second))
		for {
			n, e := stream.Read(buf)
			total += int64(n)
			if e != nil {
				break // egress closed the stream at its deadline
			}
		}
	case tunproto.SpeedUp:
		for i := 0; i+8 <= len(buf); i += 8 {
			binary.LittleEndian.PutUint64(buf[i:], mrand.Uint64())
		}
		deadline := start.Add(time.Duration(seconds) * time.Second)
		for time.Now().Before(deadline) {
			n, e := stream.Write(buf)
			total += int64(n)
			if e != nil {
				break
			}
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("no elapsed time")
	}
	return float64(total) * 8 / elapsed / 1e6, nil
}
