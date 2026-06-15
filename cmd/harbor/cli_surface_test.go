package main

// A0.6 — CLI ⊆ OpenAPI surface (the "no UI backdoor" guardrail).
//
// UI-plan principle 3 (API-first / CLI-parity): "the OpenAPI is the only admin
// surface; the CLI is a strict subset ... Enforced by a CI contract test, not a
// promise." This test is that enforcement. It reconstructs the harbor CLI's
// command tree from the source (so a NEW command can't slip through), and asserts
// every operator command maps to a real OpenAPI operation — or is explicitly
// classified as a break-glass / local command that is deliberately NOT on the API.
//
// It does NOT change CLI behavior; it is a pure guardrail. (Refactoring the CLI to
// literally call /admin/v1 over HTTP, and generating the TS client, are deferred:
// the former needs real auth — 2.11 — and the latter needs the ui/ tree.)
//
// The extractor is FAIL-CLOSED (see parseCLICommands): it models exactly one
// dispatch shape and turns anything it cannot account for into a test failure,
// because a guardrail that silently skipped an unrecognized shape would let an
// off-API command ship green — the exact hole this test exists to close.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
)

// surfaceEntry classifies one full CLI command path (e.g. "lighthouse add").
type surfaceEntry struct {
	op  string // OpenAPI operationId it maps to; "" => not an API capability
	why string // justification, required when op == "" (break-glass / local)
}

// cliSurface is the authoritative classification of every harbor command. Adding
// a CLI command without adding it here fails TestCLISurfaceSubsetOfOpenAPI — the
// author must decide: does this belong on the admin API (give its operationId) or
// is it deliberately break-glass / local (give a reason)? That decision is the
// "no UI backdoor" gate.
var cliSurface = map[string]surfaceEntry{
	// ── operator commands: each MUST map to an OpenAPI operation ───────────────
	"audit verify":       {op: "verifyAudit"},
	"fleet":              {op: "getFleetHealth"},
	"joinkey create":     {op: "createJoinKey"},
	"joinkey list":       {op: "listJoinKeys"},
	"joinkey revoke":     {op: "revokeJoinKey"},
	"enroll pending":     {op: "listEnrollments"},
	"enroll approve":     {op: "approveEnrollment"},
	"lighthouse add":     {op: "addLighthouse"},
	"lighthouse replace": {op: "replaceLighthouse"},
	"lighthouse remove":  {op: "removeLighthouse"},
	"lighthouse list":    {op: "listLighthouses"},
	"rollout start":      {op: "startRollout"},
	"rollout step":       {op: "stepRollout"},
	"rollout status":     {op: "getCurrentRollout"},
	"rollout abort":      {op: "abortRollout"},
	"policy compile":     {op: "compilePolicy"},
	"policy propose":     {op: "proposePolicy"},
	"policy approve":     {op: "approveChange"},
	"policy deny":        {op: "denyChange"},
	"policy list":        {op: "listApprovals"},
	"policy active":      {op: "getActivePolicy"},

	// ── break-glass / local: deliberately NOT on the API ──────────────────────
	"admin-token create": {why: "mints a machine token for the admin API; local bootstrap — it creates the auth, so it cannot require it"},
	"admin-token list":   {why: "lists admin API tokens; local store inspection"},
	"admin-token revoke": {why: "revokes an admin API token; local break-glass (works even if the API is down)"},
	"migrate up":         {why: "DB schema migration — infra/ops, runs before any server is up"},
	"migrate down":       {why: "DB schema rollback — infra/ops"},
	"ipam allocate":      {why: "low-level IP management; normal allocation flows through enrollment, not an operator surface"},
	"ipam release":       {why: "low-level IP management; break-glass"},
	"enroll worker":      {why: "the queue-draining daemon — a long-running service, not an operator action"},
	"collect":            {why: "the ADR-0005 pull collector daemon — a long-running service that drains registered gateways over mTLS, not an operator action"},
	"audit add":          {why: "manual audit annotation; deliberately NOT an API capability — the console must never inject audit rows (integrity)"},
	"policy validate":    {why: "local policy-file lint, touches no server state; compilePolicy is the API superset"},
	"genesis":            {why: "cluster bootstrap — runs offline before any server/CA exists"},
	"ca-init":            {why: "CA / HSM bootstrap — offline key ceremony"},
	"issue-cert":         {why: "break-glass direct cert issuance (decision 10: CLI-only break-glass path)"},
	"cloudtrust publish": {why: "operator/bootstrap publish of the cloud-trust config (two distinct operators, like genesis); the console's POST /cloudtrust/propose is the day-to-day path, this is for bootstrap/break-glass before the API is up"},
	"blocklist add":      {why: "security break-glass: blocklist a compromised host's cert (7.1) — must work even when the console is down (when you most need to kill a host). The console blocklist view + dual-control bulk-revoke land in 7.2/UI-5; single-host add is CLI-only until then"},
	"blocklist remove":   {why: "security break-glass: lift a blocklist entry (7.1); CLI-only until the UI-5 blocklist view (7.2)"},
	"blocklist list":     {why: "local store inspection of the cert blocklist (7.1); the console blocklist view lands in 7.2/UI-5"},
	"blocklist status":   {why: "local inspection of the blocklist-lane rollout convergence (7.1b); the console propagation-status view lands in 7.2/UI-5"},
	"nebula add":         {why: "register a nebula data-plane release in the distribution registry (ADR 0003 Phase 1c); admin/bootstrap action — the console Releases view lands in a later UI step (UI-Nebula-Releases)"},
	"nebula list":        {why: "local inspection of the nebula release registry (ADR 0003 Phase 1c); the console Releases view is a later UI step"},
	"nebula release":     {why: "stage a nebula version across the fleet via the nebula rollout lane (ADR 0003 Phase 1c); operator action — the console Releases view lands in a later UI step"},
	"nebula status":      {why: "local inspection of the nebula-lane rollout convergence (ADR 0003 Phase 1c); the console Releases view is a later UI step"},
	"nebula abort":       {why: "abort an in-flight nebula rollout (ADR 0003 Phase 1c); operator/break-glass — the console Releases view is a later UI step"},
	"pilot add":          {why: "register a pilot (agent) release in the distribution registry (ADR 0003 Phase 3c); admin/bootstrap action — the console Releases view lands in a later UI step"},
	"pilot list":         {why: "local inspection of the pilot release registry (ADR 0003 Phase 3c); the console Releases view is a later UI step"},
	"pilot release":      {why: "stage a pilot version across the fleet via the pilot rollout lane (ADR 0003 Phase 3c); operator action — the console Releases view lands in a later UI step"},
	"pilot status":       {why: "local inspection of the pilot-lane rollout convergence (ADR 0003 Phase 3c); the console Releases view is a later UI step"},
	"pilot abort":        {why: "abort an in-flight pilot rollout (ADR 0003 Phase 3c); operator/break-glass — the console Releases view is a later UI step"},
	"gateway add":        {why: "register a pull-based enrollment gateway in the registry (ADR 0005); admin/bootstrap action (pins the gateway's self-signed cert) — the console gateway view is a later UI step"},
	"gateway remove":     {why: "retire a registered gateway (ADR 0005); local/break-glass admin action — the console gateway view is a later UI step"},
	"gateway list":       {why: "local inspection of the gateway registry (ADR 0005); the console gateway view is a later UI step"},
	"seed-demo":          {why: "DEV/DEMO ONLY: writes a synthetic fleet straight into the store (heartbeats arrive from agents, not the API) — never a console capability"},
	"core-api":           {why: "server launcher, not an operation"},
	"admin-api":          {why: "server launcher, not an operation"},
	"version":            {why: "meta"},
	"help":               {why: "meta"},
}

// TestCLISurfaceSubsetOfOpenAPI is the A0.6 enforcement.
func TestCLISurfaceSubsetOfOpenAPI(t *testing.T) {
	actual := parseCLICommands(t)
	specOps := openAPIOperationIDs(t)

	// 1. Anti-drift: the source's command tree must exactly match cliSurface, so a
	//    newly-added (or removed) command forces a classification decision here.
	for _, path := range actual {
		if _, ok := cliSurface[path]; !ok {
			t.Errorf("CLI defines %q but it is not classified in cliSurface — add it as an operator command (with its OpenAPI operationId) or as break-glass/local (with a justification). An unclassified command is a potential UI backdoor.", path)
		}
	}
	have := map[string]bool{}
	for _, p := range actual {
		have[p] = true
	}
	for path := range cliSurface {
		if !have[path] {
			t.Errorf("cliSurface classifies %q but the CLI no longer defines it — remove the stale entry.", path)
		}
	}

	// 2. Every operator command maps to a real OpenAPI operation; every
	//    break-glass/local command carries a justification (and claims no op).
	for path, e := range cliSurface {
		switch {
		case e.op == "" && e.why == "":
			t.Errorf("%q is classified as break-glass/local but has no justification (why)", path)
		case e.op != "" && e.why != "":
			t.Errorf("%q has both an operationId and a why — it is one or the other", path)
		case e.op != "" && !specOps[e.op]:
			t.Errorf("operator command %q maps to operationId %q, which is not in the OpenAPI spec (CLI ⊄ API — a backdoor, or a renamed/removed operation)", path, e.op)
		}
	}
}

// openAPIOperationIDs returns the set of operationIds in the embedded admin spec.
// (The adminapi contract test already validates the spec is well-formed, so a
// line scan of the source of truth is sufficient and dependency-free here.)
func openAPIOperationIDs(t *testing.T) map[string]bool {
	t.Helper()
	ops := map[string]bool{}
	for _, line := range strings.Split(string(adminapi.Spec()), "\n") {
		line = strings.TrimSpace(line)
		if id, ok := strings.CutPrefix(line, "operationId:"); ok {
			if id = strings.TrimSpace(id); id != "" {
				ops[id] = true
			}
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operationIds found in the OpenAPI spec")
	}
	return ops
}

// parseCLICommands reconstructs the harbor command tree from main.go and returns
// every full command path ("genesis", "lighthouse add", ...).
//
// It is FAIL-CLOSED: the extractor models exactly one dispatch shape — a single
// switch on a positional argument (os.Args[1] at the top level; args[0] or a local
// assigned from it inside each handler), with string-literal case labels — and
// turns anything it cannot account for into a test FAILURE rather than silently
// treating it as "no sub-actions". A guardrail that silently skipped an
// unrecognized shape (an if/compare dispatch, a default-clause branch, a second
// positional switch, a const/ident case label) would let an off-API command ship
// green — the exact "no UI backdoor" hole this test exists to close.
//
// Canonical shape a new command MUST follow (or teach this extractor):
//   - top level:  case "name": cmdName(os.Args[2:])   (inside main's os.Args[1] switch)
//   - sub-actions: switch args[0] { case "sub": ... }  (or `sub := args[0]; switch sub`)
//
// Known limitation (low risk): sub-actions dispatched on a FLAG value rather than a
// positional arg (`switch *mode { case "x" }`) are not enumerated, because that is
// indistinguishable from the legitimate software|pkcs11 backend selectors the
// extractor must ignore. Such a command is still surfaced (so its classification is
// forced) — only the granularity of its sub-actions is lost — and an operator entry
// must still map to a real operationId. Don't dispatch sub-actions on a flag.
func parseCLICommands(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	// Parse the WHOLE command package, not just main.go: command handlers may live
	// in any file (e.g. admintoken.go), and the extractor must see them or it would
	// mistake a command for a leaf and miss its sub-actions (fail-open).
	var files []*ast.File
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read command dir: %v", err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		files = append(files, f)
	}
	paths, problems := extractCommands(fset, files)
	for _, p := range problems {
		t.Error(p) // a fail-closed violation: an un-modeled dispatch shape in the package
	}
	return paths
}

// extractCommands is the pure (testable) core of the extractor: it walks the parsed
// package files and returns the command tree plus any FAIL-CLOSED problems
// (un-modeled dispatch shapes). parseCLICommands feeds it the harbor package; the
// self-test TestExtractorFailsClosed feeds it synthetic sources to prove each
// dangerous shape is caught rather than silently dropped.
func extractCommands(fset *token.FileSet, files []*ast.File) (paths, problems []string) {
	addf := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}
	main, ok := funcs["main"]
	if !ok {
		addf("no func main")
		return nil, problems
	}
	top := commandSwitch(fset, main, "main", addf)
	if top == nil {
		addf("no top-level positional command switch in main()")
		return nil, problems
	}

	for _, cl := range caseClauses(top) {
		labels := commandLabels(fset, cl, "main", addf)
		// Recurse into the handler this case dispatches to (resolved by any in-file
		// function it calls — NOT a name prefix) to discover its sub-actions.
		var subs []string
		if fn := funcs[handlerFunc(cl, funcs)]; fn != nil {
			if sw := commandSwitch(fset, fn, fn.Name.Name, addf); sw != nil {
				for _, scl := range caseClauses(sw) {
					subs = append(subs, commandLabels(fset, scl, fn.Name.Name, addf)...)
				}
			}
		}
		for _, tok := range labels {
			if strings.HasPrefix(tok, "-") {
				continue // flag aliases (--version, -h) are not commands
			}
			if len(subs) == 0 {
				paths = append(paths, tok)
				continue
			}
			for _, s := range subs {
				paths = append(paths, tok+" "+s)
			}
		}
	}
	sort.Strings(paths)
	return paths, problems
}

// commandSwitch returns the sole positional-dispatch switch in fn (the command /
// sub-action selector), or nil if fn has none. It is FAIL-CLOSED: if fn dispatches
// on a positional arg in any OTHER way the extractor can't read — a second
// positional switch, or an `==`/`!=` of a positional arg against a string literal
// (an if-based dispatch, including inside a default clause) — it reports a problem,
// because those sub-actions are invisible to the guardrail and would otherwise
// ship unpoliced.
func commandSwitch(fset *token.FileSet, fn *ast.FuncDecl, name string, addf func(string, ...any)) *ast.SwitchStmt {
	positional := positionalVars(fn)
	var switches []*ast.SwitchStmt
	var strays []ast.Node
	ast.Inspect(fn, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SwitchStmt:
			if x.Tag != nil && isPositionalTag(x.Tag, positional) {
				switches = append(switches, x)
			}
		case *ast.BinaryExpr:
			if (x.Op == token.EQL || x.Op == token.NEQ) && isPositionalStringCompare(x, positional) {
				strays = append(strays, x)
			}
		}
		return true
	})
	for _, n := range strays {
		addf("%s: dispatches on a positional arg via an if/comparison at %s — the CLI-surface extractor only models a `switch` on the positional arg, so that sub-action is invisible to the guardrail. Use a switch (or teach parseCLICommands).", name, fset.Position(n.Pos()))
	}
	if len(switches) > 1 {
		for _, sw := range switches[1:] {
			addf("%s: a second positional switch at %s — the extractor models exactly one command/sub-action switch per function.", name, fset.Position(sw.Pos()))
		}
	}
	if len(switches) == 0 {
		return nil
	}
	return switches[0]
}

// positionalVars collects locals assigned directly from args[i] / os.Args[i]
// (e.g. `sub := args[0]`, `dir := args[0]`) — these stand in for a positional arg.
func positionalVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if isArgsIndex(as.Rhs[0]) {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// isPositionalTag reports whether an expr selects on a positional arg.
func isPositionalTag(e ast.Expr, positional map[string]bool) bool {
	if isArgsIndex(e) {
		return true
	}
	id, ok := e.(*ast.Ident)
	return ok && positional[id.Name]
}

// isPositionalStringCompare reports whether one side of x is a positional arg and
// the other a string literal (an if-based command dispatch).
func isPositionalStringCompare(x *ast.BinaryExpr, positional map[string]bool) bool {
	isStr := func(e ast.Expr) bool { l, ok := e.(*ast.BasicLit); return ok && l.Kind == token.STRING }
	return (isPositionalTag(x.X, positional) && isStr(x.Y)) || (isPositionalTag(x.Y, positional) && isStr(x.X))
}

// isArgsIndex reports whether e is `args[...]` or `os.Args[...]`.
func isArgsIndex(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok {
		return false
	}
	switch x := ix.X.(type) {
	case *ast.Ident:
		return x.Name == "args"
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		return ok && pkg.Name == "os" && x.Sel.Name == "Args"
	}
	return false
}

func caseClauses(sw *ast.SwitchStmt) []*ast.CaseClause {
	var out []*ast.CaseClause
	for _, s := range sw.Body.List {
		if cl, ok := s.(*ast.CaseClause); ok && len(cl.List) > 0 { // skip default
			out = append(out, cl)
		}
	}
	return out
}

// commandLabels returns the string-literal labels of a case clause (a case may
// list aliases). It is FAIL-CLOSED: a non-string-literal label (a const/ident) is
// recorded as a failure, because the extractor would otherwise silently drop that
// command/sub-action from the surface.
func commandLabels(fset *token.FileSet, cl *ast.CaseClause, name string, addf func(string, ...any)) []string {
	var out []string
	for _, e := range cl.List {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			addf("%s: non-string-literal case label at %s — the CLI-surface extractor only models string-literal command labels; use a literal (or teach parseCLICommands).", name, fset.Position(e.Pos()))
			continue
		}
		if v, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// handlerFunc returns the name of the top-level function a case dispatches to
// (recursed into for sub-actions), or "" if it handles the command inline. It does
// NOT rely on a name prefix: any function defined in this file that the case calls
// counts, so a handler named e.g. secretSurface can't hide its sub-actions the way
// a cmd*-only match would. (version -> fmt.Printf is not in-file -> leaf; help ->
// usage() is in-file but has no positional switch -> still a leaf.)
func handlerFunc(cl *ast.CaseClause, funcs map[string]*ast.FuncDecl) string {
	var name string
	ast.Inspect(cl, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && funcs[id.Name] != nil {
				name = id.Name
				return false
			}
		}
		return true
	})
	return name
}

// TestExtractorFailsClosed proves the guardrail's own integrity: the extractor
// must REPORT (not silently drop) every dispatch shape it does not model, so a
// future off-API command cannot ship with the test green. Each case feeds a
// synthetic main.go to extractCommands and asserts the fail-closed behavior.
func TestExtractorFailsClosed(t *testing.T) {
	parse := func(src string) (paths, problems []string) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v\n%s", err, src)
		}
		return extractCommands(fset, []*ast.File{f})
	}

	// A canonical, well-formed CLI parses cleanly and yields the expected tree.
	t.Run("canonical/clean", func(t *testing.T) {
		paths, problems := parse(`package main
import "os"
func main() {
	switch os.Args[1] {
	case "lighthouse": cmdLighthouse(os.Args[2:])
	case "version": _ = 0
	}
}
func cmdLighthouse(args []string) {
	switch args[0] {
	case "add":
	case "list":
	}
}`)
		if len(problems) != 0 {
			t.Fatalf("clean source reported problems: %v", problems)
		}
		want := []string{"lighthouse add", "lighthouse list", "version"}
		if strings.Join(paths, ",") != strings.Join(want, ",") {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	})

	// Each of these dispatch shapes hides a sub-action/command the extractor cannot
	// read, so it MUST be reported rather than silently dropped (fail-open).
	bad := map[string]string{
		"const case label (sub-action vanishes)": `package main
import "os"
const subWipe = "wipe"
func main() { switch os.Args[1] { case "audit": cmdAudit(os.Args[2:]) } }
func cmdAudit(args []string) { switch args[0] { case "verify": case subWipe: } }`,

		"if/compare dispatch (pre-switch guard)": `package main
import "os"
func main() { switch os.Args[1] { case "lighthouse": cmdLighthouse(os.Args[2:]) } }
func cmdLighthouse(args []string) {
	if args[0] == "purge-all" { return }
	switch args[0] { case "add": }
}`,

		"if/compare dispatch in default clause": `package main
import "os"
func main() { switch os.Args[1] { case "policy": cmdPolicy(os.Args[2:]) } }
func cmdPolicy(args []string) {
	switch args[0] {
	case "list":
	default:
		if args[0] == "rotate-key" { return }
	}
}`,

		"second positional switch": `package main
import "os"
func main() { switch os.Args[1] { case "x": cmdX(os.Args[2:]) } }
func cmdX(args []string) {
	switch args[0] { case "a": }
	switch args[0] { case "b": }
}`,

		"command dispatched outside main's switch": `package main
import "os"
func main() {
	if os.Args[1] == "debug" { cmdDebug(os.Args[2:]); return }
	switch os.Args[1] { case "x": cmdX(os.Args[2:]) }
}
func cmdDebug(args []string) {}
func cmdX(args []string) {}`,
	}
	for name, src := range bad {
		t.Run("rejects/"+name, func(t *testing.T) {
			if _, problems := parse(src); len(problems) == 0 {
				t.Fatalf("extractor reported NO problem for a shape it cannot model — fail-OPEN:\n%s", src)
			}
		})
	}

	// A handler NOT named cmd* must still have its sub-actions surfaced (so the
	// catalog check can force their classification) — not hidden by a name prefix.
	t.Run("non-cmd handler still surfaces sub-actions", func(t *testing.T) {
		paths, problems := parse(`package main
import "os"
func main() { switch os.Args[1] { case "secret": secretSurface(os.Args[2:]) } }
func secretSurface(args []string) { switch args[0] { case "grant": case "revoke": } }`)
		if len(problems) != 0 {
			t.Fatalf("unexpected problems: %v", problems)
		}
		got := strings.Join(paths, ",")
		if !strings.Contains(got, "secret grant") || !strings.Contains(got, "secret revoke") {
			t.Fatalf("non-cmd handler sub-actions not surfaced: %v", paths)
		}
	})
}
