package main

import (
	"flag"
	"fmt"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
)

// cmdProbe tests every endpoint (mimic) of a node individually and reports which
// are reachable and which are blocked — the fast way to see, per node, which
// camouflage protocols actually work on the current network path.
func cmdProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	nodeAlias := fs.String("node", "", "node alias (default: all nodes)")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil {
		fail("no config: %v", err)
	}
	if cfg.Role != "iran" {
		fail("probe runs on the Iran hub")
	}

	nodes := cfg.ForeignNodes
	if *nodeAlias != "" {
		nodes = nil
		for _, n := range cfg.ForeignNodes {
			if n.Alias == *nodeAlias {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			fail("node %q not found", *nodeAlias)
		}
	}
	if len(nodes) == 0 {
		fail("no foreign nodes configured")
	}

	anyFail := false
	for _, n := range nodes {
		if n.Reverse {
			color.Yellow("\nNode %q is in reverse mode: the foreign dials in, so there is nothing to probe from here.", n.Alias)
			color.Yellow("  Look for \"reverse pipe established\" in: journalctl -u hedioum.service")
			continue
		}
		fmt.Printf("\nNode %q (%d endpoints):\n", n.Alias, len(n.Endpoints))
		for _, ep := range n.Endpoints {
			rtt, err := ingress.ProbeEndpoint(ep, n.AuthToken)
			if err != nil {
				anyFail = true
				color.Red("  ✗ %-6s %-24s FAIL: %v", ep.Mimic, ep.Target, err)
			} else {
				color.Green("  ✓ %-6s %-24s OK  (%.0f ms)", ep.Mimic, ep.Target, float64(rtt.Microseconds())/1000)
			}
		}
	}
	if anyFail {
		// Non-zero exit so scripts/CI can detect a degraded path.
		fail("one or more endpoints are unreachable")
	}
}
