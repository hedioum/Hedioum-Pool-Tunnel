package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
)

// Several hubs for one reverse foreign. The foreign is the side that dials, so each
// hub it dials has its own pipe range (min..max) kept here; the hub keeps shaping
// (bandwidth, jitter) and its own max_connections cap on the node. A foreign with a
// single hub keeps using reverse_targets/reverse_conns unchanged.

const maxHubConns = 200

func validPipeRange(min, max int) error {
	switch {
	case min < 1 || min > maxHubConns:
		return fmt.Errorf("--min must be between 1 and %d", maxHubConns)
	case max < min || max > maxHubConns:
		return fmt.Errorf("--max must be between --min and %d", maxHubConns)
	}
	return nil
}

func hubIndex(cfg *config.AppConfig, name string) int {
	for i, h := range cfg.ReverseHubs {
		if h.Name == name {
			return i
		}
	}
	return -1
}

// promoteLegacyHub turns the single-hub fields into the first ReverseHubs entry so a
// second hub can be added next to it.
func promoteLegacyHub(cfg *config.AppConfig) {
	if len(cfg.ReverseHubs) > 0 || len(cfg.ReverseTargets) == 0 {
		return
	}
	cfg.ReverseHubs = cfg.EffectiveReverseHubs()
	for i := range cfg.ReverseHubs {
		cfg.ReverseHubs[i].AuthToken = "" // the foreign's own token, as before
	}
}

// applyAddHub adds the hub a reverse pairing token describes (or replaces the one of the
// same name). min/max of 0 take the defaults (12, fixed). keep also keeps the normal
// inbound listeners when this is the first reverse hub of a forward-mode foreign.
func applyAddHub(cfg *config.AppConfig, token, name string, min, max int, keep bool) (config.ReverseHub, error) {
	pt, isV2, err := pairing.Decode(token)
	if err != nil || !isV2 || pt == nil {
		return config.ReverseHub{}, fmt.Errorf("the token must be a reverse pairing token from `reverse-iran` (%v)", err)
	}
	if !pt.Reverse {
		return config.ReverseHub{}, fmt.Errorf("this is a normal pairing token; get a reverse one by running `reverse-iran` on the hub")
	}
	targets := reverseTargetsFromToken(pt)
	if len(targets) == 0 {
		return config.ReverseHub{}, fmt.Errorf("the token has no usable reverse endpoints")
	}
	if min == 0 {
		min = config.DefaultReverseConns
	}
	if max == 0 {
		max = min
	}
	if err := validPipeRange(min, max); err != nil {
		return config.ReverseHub{}, err
	}
	if name == "" {
		name = strings.NewReplacer(".", "-", ":", "-").Replace(pt.ExitIP)
	}
	if strings.ContainsAny(name, " \t,") {
		return config.ReverseHub{}, fmt.Errorf("--name must not contain spaces or commas")
	}

	promoteLegacyHub(cfg)
	hub := config.ReverseHub{Name: name, Targets: targets, MinConns: min, MaxConns: max}
	if pt.AuthKey != cfg.AuthToken {
		hub.AuthToken = pt.AuthKey // this hub knows the foreign by a different token
	}
	if i := hubIndex(cfg, name); i >= 0 {
		cfg.ReverseHubs[i] = hub
	} else {
		for _, h := range cfg.ReverseHubs {
			if len(h.Targets) > 0 && h.Targets[0].Target == targets[0].Target {
				return config.ReverseHub{}, fmt.Errorf("hub %q already dials %s; use edit-hub to change it", h.Name, targets[0].Target)
			}
		}
		cfg.ReverseHubs = append(cfg.ReverseHubs, hub)
	}
	if len(cfg.ReverseHubs) == 1 && !cfg.ReverseOnly {
		cfg.ReverseOnly = !keep
	}
	cfg.SyncReverseCompat()
	return hub, nil
}

// applyEditHub changes a hub's pipe range; 0 keeps the current value.
func applyEditHub(cfg *config.AppConfig, name string, min, max int) error {
	promoteLegacyHub(cfg)
	i := hubIndex(cfg, name)
	if i < 0 {
		return fmt.Errorf("no hub named %q (see list-hubs)", name)
	}
	cur := cfg.EffectiveReverseHubs()[i]
	if min == 0 {
		min = cur.MinConns
	}
	if max == 0 {
		max = cur.MaxConns
		if max < min {
			max = min
		}
	}
	if err := validPipeRange(min, max); err != nil {
		return err
	}
	cfg.ReverseHubs[i].MinConns, cfg.ReverseHubs[i].MaxConns = min, max
	cfg.SyncReverseCompat()
	return nil
}

// applyRemoveHub drops a hub. The last one cannot be removed this way: that is leaving
// reverse mode (reverse-foreign --forward).
func applyRemoveHub(cfg *config.AppConfig, name string) error {
	promoteLegacyHub(cfg)
	i := hubIndex(cfg, name)
	if i < 0 {
		return fmt.Errorf("no hub named %q (see list-hubs)", name)
	}
	if len(cfg.ReverseHubs) == 1 {
		return fmt.Errorf("%q is the only hub; use `reverse-foreign --forward` to leave reverse mode", name)
	}
	cfg.ReverseHubs = append(cfg.ReverseHubs[:i], cfg.ReverseHubs[i+1:]...)
	cfg.SyncReverseCompat()
	return nil
}

func loadForeign() *config.AppConfig {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config (run this on the foreign; setup-foreign first)")
	}
	return cfg
}

func saveAndRestartForeign(cfg *config.AppConfig) {
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	reconcileUnit("foreign")
	restartDaemon()
}

func pipeRangeText(h config.ReverseHub) string {
	if h.MaxConns <= h.MinConns {
		return fmt.Sprintf("%d pipes", h.MinConns)
	}
	return fmt.Sprintf("%d-%d pipes", h.MinConns, h.MaxConns)
}

func printHubs(cfg *config.AppConfig) {
	hubs := cfg.EffectiveReverseHubs()
	if len(hubs) == 0 {
		fmt.Println("This foreign dials no hub (normal mode).")
		return
	}
	for _, h := range hubs {
		var eps []string
		for _, ep := range h.Targets {
			eps = append(eps, ep.Mimic+"@"+ep.Target)
		}
		fmt.Printf("  %-18s %-14s %s\n", h.Name, pipeRangeText(h), strings.Join(eps, ", "))
	}
}

// cmdAddHub makes the foreign dial one more hub.
func cmdAddHub(args []string) {
	fs := flag.NewFlagSet("add-hub", flag.ExitOnError)
	token := fs.String("token", "", "reverse pairing token printed by `reverse-iran` on that hub")
	name := fs.String("name", "", "a label for the hub (default: its IP)")
	min := fs.Int("min", 0, "pipes always kept open to this hub (default 12)")
	max := fs.Int("max", 0, "most pipes opened under load (default: same as --min, i.e. fixed)")
	keep := fs.Bool("keep-listeners", false, "when this is the first reverse hub, also keep the normal inbound listeners")
	_ = fs.Parse(args)
	if *token == "" {
		fail("--token is required (the reverse pairing token printed by `reverse-iran` on the hub)")
	}
	cfg := loadForeign()
	hub, err := applyAddHub(cfg, *token, *name, *min, *max, *keep)
	if err != nil {
		fail("%v", err)
	}
	color.Green("[✓] Hub %q added: %s across %d endpoint(s).", hub.Name, pipeRangeText(hub), len(hub.Targets))
	if hub.MinConns < 3 {
		color.Yellow("    [!] The hub keeps its first 2 pipes for UDP, so use --min 3 or more to leave a TCP pipe.")
	}
	color.Yellow("    Keep the hub node's max_connections at or above --max, or the hub drops the extra pipes.")
	saveAndRestartForeign(cfg)
}

// cmdEditHub changes a hub's pipe range.
func cmdEditHub(args []string) {
	fs := flag.NewFlagSet("edit-hub", flag.ExitOnError)
	name := fs.String("name", "", "hub label (see list-hubs)")
	min := fs.Int("min", 0, "pipes always kept open (0 = keep)")
	max := fs.Int("max", 0, "most pipes opened under load (0 = keep)")
	_ = fs.Parse(args)
	if *name == "" {
		fail("--name is required")
	}
	cfg := loadForeign()
	if err := applyEditHub(cfg, *name, *min, *max); err != nil {
		fail("%v", err)
	}
	color.Green("[✓] Hub %q updated.", *name)
	printHubs(cfg)
	saveAndRestartForeign(cfg)
}

// cmdRemoveHub stops dialing a hub.
func cmdRemoveHub(args []string) {
	fs := flag.NewFlagSet("remove-hub", flag.ExitOnError)
	name := fs.String("name", "", "hub label (see list-hubs)")
	_ = fs.Parse(args)
	if *name == "" {
		fail("--name is required")
	}
	cfg := loadForeign()
	if err := applyRemoveHub(cfg, *name); err != nil {
		fail("%v", err)
	}
	color.Green("[✓] Hub %q removed.", *name)
	saveAndRestartForeign(cfg)
}

// cmdListHubs prints the hubs this foreign dials.
func cmdListHubs(args []string) {
	_ = flag.NewFlagSet("list-hubs", flag.ExitOnError).Parse(args)
	printHubs(loadForeign())
}
