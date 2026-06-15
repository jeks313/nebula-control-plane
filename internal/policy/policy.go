// Package policy is Harbor's central firewall policy (implementation-plan M6,
// solves pain #4). It is a group-based, allow-only DSL with an implicit
// default-deny (6.1); a compiler that turns the global policy into each host's
// per-host Nebula firewall section (6.2); and compile-time invariants so a
// published policy can never sever the control plane or lighthouse discovery
// (6.3, design §P10).
package policy

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
)

// Reserved groups whose reachability is guaranteed by the baseline and must not
// be shaped by user rules (6.3).
const (
	GroupControlPlane = "control-plane"
	GroupLighthouse   = "lighthouse"
)

// PublishKind is the dual-control change kind for firewall-policy publish (6.5).
// The active fleet policy is the latest committed change of this kind. Shared by
// the CLI and the admin API so both write/read the same records.
const PublishKind = "policy.publish"

// RegisterCommitter installs the policy.publish commit-time validator on dc. This
// is the single canonical definition every wiring site (harbor CLI, admin API,
// demo seeder) uses, so a published policy is committed through the SAME
// validation and the gate can't drift by call site. Re-validating at commit is
// defense in depth — invariants are also checked at propose time.
func RegisterCommitter(dc *dualcontrol.Controller) {
	dc.Register(PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		p, err := Parse(string(ch.Payload))
		if err != nil {
			return err
		}
		return CheckInvariants(p)
	})
}

// Rule is one allow rule: members of FromGroup may reach members of ToGroup on
// Proto/Port. "any" is allowed for FromGroup (any source) and Port.
type Rule struct {
	FromGroup string `json:"from"`
	ToGroup   string `json:"to"`
	Proto     string `json:"proto"` // tcp | udp | icmp | any
	Port      string `json:"port"`  // any | N | N-M
}

// Policy is the fleet-wide allow-list. No rule matching a host => default-deny.
type Policy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Compiled is a host's resolved firewall section.
type Compiled struct {
	Inbound  []nebulaconfig.Rule
	Outbound []nebulaconfig.Rule
}

// Parse reads the DSL: one `allow <from> -> <to> <proto> <port>` per line;
// blank lines and `#` comments ignored. Groups may be bare or `group:`-prefixed;
// `any` is a wildcard source/destination.
func Parse(text string) (Policy, error) {
	var p Policy
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		// allow <from> -> <to> <proto> <port>
		if len(f) != 6 || f[0] != "allow" || f[2] != "->" {
			return Policy{}, fmt.Errorf("policy: line %d: want `allow <from> -> <to> <proto> <port>`, got %q", i+1, line)
		}
		p.Rules = append(p.Rules, Rule{
			FromGroup: stripGroup(f[1]), ToGroup: stripGroup(f[3]),
			Proto: strings.ToLower(f[4]), Port: f[5],
		})
	}
	if err := Validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func stripGroup(s string) string { return strings.TrimPrefix(s, "group:") }

// Validate checks every rule is well-formed (6.1). An empty policy is valid
// (it means default-deny everywhere).
func Validate(p Policy) error {
	for i, r := range p.Rules {
		if r.FromGroup == "" || r.ToGroup == "" {
			return fmt.Errorf("policy: rule %d: empty group", i)
		}
		switch r.Proto {
		case "tcp", "udp", "icmp", "any":
		default:
			return fmt.Errorf("policy: rule %d: bad proto %q", i, r.Proto)
		}
		if err := validatePort(r.Port); err != nil {
			return fmt.Errorf("policy: rule %d: %w", i, err)
		}
	}
	return nil
}

func validatePort(p string) error {
	if p == "any" {
		return nil
	}
	lo, hi, ok := strings.Cut(p, "-")
	check := func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("bad port %q", p)
		}
		return nil
	}
	if !ok {
		return check(p)
	}
	if err := check(lo); err != nil {
		return err
	}
	return check(hi)
}

// CheckInvariants rejects a policy that would shape reachability to/from the
// reserved control-plane / lighthouse groups (6.3): that reachability is owned
// by the baseline (so it can never be removed), and user rules must not touch it.
func CheckInvariants(p Policy) error {
	for i, r := range p.Rules {
		for _, g := range []string{r.FromGroup, r.ToGroup} {
			if g == GroupControlPlane || g == GroupLighthouse {
				return fmt.Errorf("policy: rule %d references reserved group %q — its reachability is guaranteed by the baseline and cannot be shaped by policy", i, g)
			}
		}
	}
	return nil
}

// CompileHost resolves the policy to a host's firewall section (6.2), then
// injects the mandatory baseline (6.3): every host can always reach the control
// plane (renew/heartbeat) and use ICMP; control-plane hosts always accept the
// mesh. Only rules touching the host's groups are emitted.
func CompileHost(p Policy, hostGroups []string) Compiled {
	hg := make(map[string]bool, len(hostGroups))
	for _, g := range hostGroups {
		hg[g] = true
	}
	var c Compiled

	for _, r := range p.Rules {
		if r.ToGroup == "any" || hg[r.ToGroup] {
			c.Inbound = append(c.Inbound, selector(r.Proto, r.Port, r.FromGroup))
		}
		if r.FromGroup == "any" || hg[r.FromGroup] {
			c.Outbound = append(c.Outbound, selector(r.Proto, r.Port, r.ToGroup))
		}
	}

	// Baseline (invariant): cannot be removed by any policy.
	if hg[GroupControlPlane] {
		// Core must accept the mesh (its API auth is tunnel-identity, §4.2).
		c.Inbound = append(c.Inbound, nebulaconfig.Rule{Proto: "any", Port: "any", Host: "any"})
	} else {
		// Every member can reach the control plane (renew/heartbeat).
		c.Outbound = append(c.Outbound, nebulaconfig.Rule{Proto: "any", Port: "any", Group: GroupControlPlane})
	}
	// ICMP both ways (liveness/keepalive).
	c.Inbound = append(c.Inbound, nebulaconfig.Rule{Proto: "icmp", Port: "any", Host: "any"})
	c.Outbound = append(c.Outbound, nebulaconfig.Rule{Proto: "icmp", Port: "any", Host: "any"})

	c.Inbound = dedup(c.Inbound)
	c.Outbound = dedup(c.Outbound)
	return c
}

func selector(proto, port, group string) nebulaconfig.Rule {
	if group == "any" {
		return nebulaconfig.Rule{Proto: proto, Port: port, Host: "any"}
	}
	return nebulaconfig.Rule{Proto: proto, Port: port, Group: group}
}

func dedup(rules []nebulaconfig.Rule) []nebulaconfig.Rule {
	seen := make(map[string]bool, len(rules))
	out := rules[:0]
	for _, r := range rules {
		k := r.Proto + "|" + r.Port + "|" + r.Host + "|" + r.Group
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}
