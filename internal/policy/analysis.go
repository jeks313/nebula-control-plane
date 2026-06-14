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

// FlowDelta is one permitted flow that changed between two policies, for a literal
// (as-written) ordered group pair. `from`/`to` are the literal rule groups (so an
// any-source rule appears as from=="any", not fanned out across every group).
type FlowDelta struct {
	From string `json:"from"`
	To   string `json:"to"`
	Flow Flow   `json:"flow"`
}

// DiffResult is the user-rule reachability change from an active policy to a draft.
// Added = a flow the draft permits that the active policy did not; Removed = a flow the
// active policy permitted that the draft drops. The always-on baseline (control-plane
// reachability + ICMP) is identical under any policy and is excluded. Direction is
// preserved (per ordered from->to pair); duplicate/re-ordered rules normalize away.
type DiffResult struct {
	Added   []FlowDelta `json:"added"`
	Removed []FlowDelta `json:"removed"`
}

// FlowDiff computes the user-rule flow delta between two policies. It diffs the
// flows of each LITERAL group pair named in either policy (matching rules by exact
// FromGroup/ToGroup, so `any` is represented as itself rather than fanned out across
// concrete groups — that fan-out is for reachability/blast-radius, not for "what the
// proposer changed"). Flows are deduped per (proto,port); rule order/duplicates do
// not register as a change.
func FlowDiff(active, draft Policy) DiffResult {
	res := DiffResult{Added: []FlowDelta{}, Removed: []FlowDelta{}}
	for _, pr := range unionLiteralPairs(active, draft) {
		a := literalFlows(active, pr[0], pr[1])
		d := literalFlows(draft, pr[0], pr[1])
		for _, f := range flowsMinus(d, a) {
			res.Added = append(res.Added, FlowDelta{From: pr[0], To: pr[1], Flow: f})
		}
		for _, f := range flowsMinus(a, d) {
			res.Removed = append(res.Removed, FlowDelta{From: pr[0], To: pr[1], Flow: f})
		}
	}
	return res
}

// literalFlows returns the distinct flows of rules whose groups are EXACTLY from/to
// (no `any` fan-out — unlike ruleFlows). Used by FlowDiff so a change to an
// any-source rule shows once, as an `any` row, not duplicated across every group.
// Ports are canonicalized so a single-value range (443-443) and its scalar (443) do
// not register as a spurious change.
func literalFlows(p Policy, from, to string) []Flow {
	var flows []Flow
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if r.FromGroup != from || r.ToGroup != to {
			continue
		}
		port := canonPort(r.Port)
		k := r.Proto + "|" + port
		if !seen[k] {
			seen[k] = true
			flows = append(flows, Flow{Proto: r.Proto, Port: port})
		}
	}
	return flows
}

// canonPort canonicalizes a port spec so reachability-identical forms compare equal in
// a diff: a single-value range N-N is the scalar N (Parse keeps the author's raw text).
// Genuinely different ranges (e.g. 443-445) pass through unchanged.
func canonPort(port string) string {
	if lo, hi, ok := strings.Cut(port, "-"); ok && lo == hi {
		return lo
	}
	return port
}

// flowsMinus returns the flows in a that are not in b (set difference by proto|port).
func flowsMinus(a, b []Flow) []Flow {
	inB := map[string]bool{}
	for _, f := range b {
		inB[f.Proto+"|"+f.Port] = true
	}
	var out []Flow
	for _, f := range a {
		if !inB[f.Proto+"|"+f.Port] {
			out = append(out, f)
		}
	}
	return out
}

// unionLiteralPairs returns the sorted distinct literal (from,to) group pairs that
// appear in either policy's rules.
func unionLiteralPairs(active, draft Policy) [][2]string {
	set := map[[2]string]bool{}
	for _, p := range []Policy{active, draft} {
		for _, r := range p.Rules {
			set[[2]string{r.FromGroup, r.ToGroup}] = true
		}
	}
	out := make([][2]string, 0, len(set))
	for pr := range set {
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// BlastResult is the host-level impact of a policy change: the real hosts in the
// groups named by changed flows. A rule A->B compiles to A's outbound AND B's inbound
// (CompileHost), so a changed A->B flow's affected hosts are group A ∪ group B. This
// is a CONSERVATIVE SUPERSET of the hosts whose compiled firewall literally changes —
// a flow already subsumed by a broader `any` rule can leave a host's compiled output
// byte-identical, yet that host is still counted (safe for a "this affects N hosts"
// review). `Total` is the issued-host population (the denominator).
type BlastResult struct {
	Hosts []string `json:"hosts"` // overlay IPs in the changed flows' groups (sorted, superset)
	Count int      `json:"count"` // = len(Hosts)
	Total int      `json:"total"` // total issued hosts in the fleet
}

// BlastRadius resolves a flow diff to the set of real hosts potentially affected — the
// members of the changed rules' groups (a conservative superset; see BlastResult).
// groupHosts maps a group name to the overlay IPs issued that group; allHosts is the
// full issued population (used for an `any` rule side, which touches every host). It
// is pure over the injected membership (the DB read lives in the caller).
func BlastRadius(diff DiffResult, groupHosts map[string][]string, allHosts []string) BlastResult {
	affected := map[string]bool{}
	touch := func(group string) {
		if group == "any" {
			for _, h := range allHosts {
				affected[h] = true
			}
			return
		}
		for _, h := range groupHosts[group] {
			affected[h] = true
		}
	}
	for _, deltas := range [][]FlowDelta{diff.Added, diff.Removed} {
		for _, d := range deltas {
			touch(d.From)
			touch(d.To)
		}
	}
	hosts := make([]string, 0, len(affected))
	for h := range affected {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return BlastResult{Hosts: hosts, Count: len(hosts), Total: len(allHosts)}
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
