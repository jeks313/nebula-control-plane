package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Analysis (A1): pure, server-computed answers to "what does this policy permit?" — the
// authoritative reachability/matrix/test primitives the console renders but never
// recomputes (P-UI-1). Defined in terms of the SAME rule + baseline semantics CompileHost
// enforces: a single `allow A -> B p/port` rule is compiled into BOTH A's outbound and
// B's inbound, so one matching rule grants reachability for that pair; the non-removable
// baseline (every host reaches the control plane; ICMP both ways) is layered on top.

// Decision is the result of a reachability query.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`            // rule | baseline-control-plane | baseline-icmp | default-deny
	Rule    *Rule  `json:"rule,omitempty"`    // the granting rule (reason==rule)
	Nearest *Rule  `json:"nearest,omitempty"` // on deny: a rule matching from->to but wrong proto/port
}

// Reachable evaluates whether traffic from group `from` to group `to` on proto/port is
// permitted by the policy + baseline. proto is tcp|udp|icmp|any; port is any|N. A wildcard
// (any) query asks "is anything of this kind allowed".
func Reachable(p Policy, from, to, proto, port string) Decision {
	proto = strings.ToLower(proto)

	// Baseline that applies regardless of rules (cannot be shaped/removed, 6.3): ICMP both
	// ways, and every NON-control-plane host can reach the control plane on any/any. (A
	// control-plane host's outbound is only the ICMP baseline — CompileHost gives it
	// inbound any/any but no general outbound — so control-plane -> X falls through to rule
	// evaluation, mirroring enforcement.)
	if proto == "icmp" {
		return Decision{Allowed: true, Reason: "baseline-icmp"}
	}
	if to == GroupControlPlane && from != GroupControlPlane {
		return Decision{Allowed: true, Reason: "baseline-control-plane"}
	}

	// User rules. Each query dimension is evaluated independently: a wildcard (any) query
	// dimension waives only ITS OWN constraint; a concrete dimension must still be
	// permitted by the rule — so (udp, any) requires a UDP rule and (any, 22) requires a
	// rule whose port covers 22. This is exactly what CompileHost enforces per packet.
	var nearest *Rule
	for i := range p.Rules {
		r := &p.Rules[i]
		if !matchGroup(r.FromGroup, from) || !matchGroup(r.ToGroup, to) {
			continue
		}
		if matchProto(r.Proto, proto) && matchPort(r.Port, port) {
			rule := *r
			return Decision{Allowed: true, Reason: "rule", Rule: &rule}
		}
		if nearest == nil { // same group pair, wrong proto/port — the nearest miss
			n := *r
			nearest = &n
		}
	}

	// "Is anything at all reachable?" — even with no user rule, the ICMP baseline grants
	// something, so a fully-wildcard query is reachable (via baseline).
	if proto == "any" && port == "any" {
		return Decision{Allowed: true, Reason: "baseline-icmp"}
	}
	return Decision{Allowed: false, Reason: "default-deny", Nearest: nearest}
}

// Flow is a permitted (proto, port) between two groups.
type Flow struct {
	Proto string `json:"proto"`
	Port  string `json:"port"`
}

// MatrixCell is one from->to entry of the reachability matrix: the policy-permitted flows
// (user rules only — the always-on baseline is flagged separately so the grid shows the
// interesting reachability, not a wall of ICMP).
type MatrixCell struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Flows    []Flow `json:"flows"`
	Baseline bool   `json:"baseline"` // to is the control plane (always reachable, any/any)
}

// MatrixResult is the all-pairs reachability grid over a group set.
type MatrixResult struct {
	Groups []string     `json:"groups"`
	Cells  []MatrixCell `json:"cells"`
}

// Matrix computes the all-pairs (group x group) reachability grid. groups defaults to the
// distinct non-"any" groups named in the policy.
func Matrix(p Policy, groups []string) MatrixResult {
	if len(groups) == 0 {
		groups = PolicyGroups(p)
	}
	cells := make([]MatrixCell, 0, len(groups)*len(groups))
	for _, from := range groups {
		for _, to := range groups {
			cells = append(cells, MatrixCell{From: from, To: to, Flows: ruleFlows(p, from, to), Baseline: to == GroupControlPlane})
		}
	}
	return MatrixResult{Groups: groups, Cells: cells}
}

// PolicyGroups returns the sorted distinct non-wildcard groups named in the policy.
func PolicyGroups(p Policy) []string {
	set := map[string]bool{}
	for _, r := range p.Rules {
		for _, g := range []string{r.FromGroup, r.ToGroup} {
			if g != "" && g != "any" {
				set[g] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func ruleFlows(p Policy, from, to string) []Flow {
	var flows []Flow
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !matchGroup(r.FromGroup, from) || !matchGroup(r.ToGroup, to) {
			continue
		}
		k := r.Proto + "|" + r.Port
		if !seen[k] {
			seen[k] = true
			flows = append(flows, Flow{Proto: r.Proto, Port: r.Port})
		}
	}
	return flows
}

// Assertion is one policy test: an expected allow/deny for a reachability query.
type Assertion struct {
	Expect bool   `json:"expect"` // true = allow, false = deny
	From   string `json:"from"`
	To     string `json:"to"`
	Proto  string `json:"proto"`
	Port   string `json:"port"`
	Line   int    `json:"line"`
}

// TestResult pairs an assertion with the actual decision.
type TestResult struct {
	Assertion Assertion `json:"assertion"`
	Got       bool      `json:"got"`  // actual reachability
	Pass      bool      `json:"pass"` // got == expect
	Reason    string    `json:"reason"`
}

// ParseTests reads the test DSL: one `assert allow|deny <from> -> <to> <proto> <port>`
// per line; blank lines and `#` comments ignored.
func ParseTests(text string) ([]Assertion, error) {
	var out []Assertion
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		// assert allow|deny <from> -> <to> <proto> <port>
		if len(f) != 7 || f[0] != "assert" || (f[1] != "allow" && f[1] != "deny") || f[3] != "->" {
			return nil, fmt.Errorf("policy test: line %d: want `assert allow|deny <from> -> <to> <proto> <port>`, got %q", i+1, line)
		}
		a := Assertion{
			Expect: f[1] == "allow",
			From:   stripGroup(f[2]), To: stripGroup(f[4]),
			Proto: strings.ToLower(f[5]), Port: f[6], Line: i + 1,
		}
		if err := ValidateQuery(a.Proto, a.Port); err != nil {
			return nil, fmt.Errorf("policy test: line %d: %w", i+1, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// ValidateQuery checks a reachability query's proto/port are well-formed (so a typo'd
// query returns a 400 rather than a confident, misleading default-deny).
func ValidateQuery(proto, port string) error {
	switch strings.ToLower(proto) {
	case "tcp", "udp", "icmp", "any":
	default:
		return fmt.Errorf("bad proto %q (want tcp|udp|icmp|any)", proto)
	}
	if port == "any" {
		return nil
	}
	return validatePort(port)
}

// RunTests evaluates assertions against the policy.
func RunTests(p Policy, assertions []Assertion) []TestResult {
	out := make([]TestResult, 0, len(assertions))
	for _, a := range assertions {
		d := Reachable(p, a.From, a.To, a.Proto, a.Port)
		out = append(out, TestResult{Assertion: a, Got: d.Allowed, Pass: d.Allowed == a.Expect, Reason: d.Reason})
	}
	return out
}

func matchGroup(ruleGroup, q string) bool { return ruleGroup == "any" || ruleGroup == q }

// matchProto/matchPort: a wildcard QUERY (q=="any") asks "any value of this dimension",
// so any rule value qualifies; otherwise the rule must permit the concrete query value
// ("any" on the RULE side permits everything).
func matchProto(ruleProto, q string) bool {
	if q == "any" {
		return true
	}
	return ruleProto == "any" || ruleProto == q
}

func matchPort(rulePort, q string) bool {
	if q == "any" || rulePort == "any" {
		return true
	}
	qn, err := strconv.Atoi(q)
	if err != nil {
		return false
	}
	lo, hi, ok := strings.Cut(rulePort, "-")
	if !ok {
		rn, err := strconv.Atoi(rulePort)
		return err == nil && rn == qn
	}
	lon, e1 := strconv.Atoi(lo)
	hin, e2 := strconv.Atoi(hi)
	return e1 == nil && e2 == nil && qn >= lon && qn <= hin
}
