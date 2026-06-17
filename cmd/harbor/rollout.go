package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
)

// Harbor blocklist + staged-rollout commands (split from main.go).

// cmdBlocklist manages the cert blocklist (7.1, design §4.7). A blocklisted
// fingerprint is refused mesh-wide PEER-SIDE: every other host stops handshaking
// with it once they pull the next signed bundle (run core-api / enroll with
// -blocklist-db so the blocklist is sourced live). Target a cert by -fingerprint,
// or by -device (overlay IP) to resolve the host's current fingerprint from its
// enrollment. Bulk revoke + the can't-blocklist-control-plane invariant land in 7.2.
func cmdBlocklist(args []string) {
	if len(args) < 1 {
		fatalf("blocklist: want add|remove|list|status")
	}
	sub := args[0]
	fs := flag.NewFlagSet("blocklist "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	fp := fs.String("fingerprint", "", "cert fingerprint (hex sha256) to blocklist")
	device := fs.String("device", "", "overlay IP of a host; resolves to its current cert fingerprint")
	reason := fs.String("reason", "", "why (recorded in the audit trail)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	// Staged fast-propagation (7.1b): add/remove pace the push as a blocklist-lane
	// rollout (canary -> widen -> freeze on an unhealthy canary). core-api drives it
	// on heartbeats. -no-rollout skips it (the change still propagates at renewal).
	noRollout := fs.Bool("no-rollout", false, "skip the staged fast-push; rely on each host's next renewal to propagate")
	canary := fs.Int("canary", 1, "canary wave size for the staged blocklist rollout")
	waveSize := fs.Int("wave-size", 0, "hosts per post-canary wave (0 = all remaining in one wave)")
	observe := fs.Duration("observe", 5*time.Minute, "per-wave convergence window before judging it stuck")
	missingAfter := fs.Duration("missing-after", 3*time.Minute, "heartbeat silence => host considered down")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := revocation.New(s.DB, audit)
	eng := rollout.New(s.DB, audit)
	ctx := context.Background()

	// resolve turns -fingerprint / -device into a concrete fingerprint to target.
	resolve := func() string {
		switch {
		case *fp != "":
			return *fp
		case *device != "":
			var e enrollment.Enrollment
			err := s.DB.WithContext(ctx).
				Where("overlay_ip = ? AND status = ?", *device, enrollment.StatusIssued).
				Order("id DESC").First(&e).Error
			if err != nil {
				fatalf("blocklist: no issued device at overlay IP %s: %v", *device, err)
			}
			if e.Fingerprint == "" {
				fatalf("blocklist: device %s has no recorded fingerprint (issued before M7.1?) — pass -fingerprint", *device)
			}
			return e.Fingerprint
		default:
			fatalf("blocklist %s: -fingerprint or -device is required", sub)
			return ""
		}
	}

	// startRollout paces a blocklist change across the healthy fleet (7.1b). The
	// blocklist CONTENT is already the latest active set; this only stages WHO is
	// told to refetch (canary first), freezing if the canary goes unhealthy.
	startRollout := func() {
		if *noRollout {
			fmt.Println("note: -no-rollout — the change propagates at each host's next renewal (slow path)")
			return
		}
		var ips []string
		if err := s.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
			fatalf("blocklist: read fleet: %v", err)
		}
		target := eng.BlocklistVersion(ctx) + 1
		r, err := eng.Start(ctx, rollout.StartConfig{
			Lane: rollout.LaneBlocklist, Description: "blocklist change",
			TargetVersion: target, PrevVersion: target - 1, Hosts: ips,
			CanarySize: *canary, WaveSize: *waveSize, Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		switch {
		case errors.Is(err, rollout.ErrNoHosts):
			fmt.Println("note: no fleet heartbeats yet — the change propagates at renewal; no rollout started")
		case errors.Is(err, rollout.ErrActiveExists):
			fmt.Println("note: a blocklist rollout is already in flight — this change rides the latest content and converges with it")
		case err != nil:
			fatalf("blocklist: start rollout: %v", err)
		default:
			fmt.Printf("staged blocklist rollout v%d to %d host(s) (canary %d); core-api drives convergence on heartbeats\n", r.TargetVersion, len(ips), *canary)
		}
	}

	switch sub {
	case "add":
		f := resolve()
		switch _, err := reg.Add(ctx, f, *reason, *actor); {
		case errors.Is(err, revocation.ErrAlreadyActive):
			fmt.Printf("already blocklisted %s\n", f)
		case err != nil:
			fatalf("blocklist add: %v", err)
		default:
			fmt.Printf("blocklisted %s\n", f)
			startRollout()
		}
	case "remove":
		f := resolve()
		var active int64
		s.DB.WithContext(ctx).Table("revocations").Where("fingerprint = ? AND state = ?", f, revocation.StateActive).Count(&active)
		if err := reg.Lift(ctx, f, *actor); err != nil {
			fatalf("blocklist remove: %v", err)
		}
		if active == 0 {
			fmt.Printf("not blocklisted: %s\n", f)
			return
		}
		fmt.Printf("lifted blocklist for %s\n", f)
		startRollout()
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("blocklist list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no revocations")
			return
		}
		fmt.Printf("%-64s %-7s %-5s %s\n", "FINGERPRINT", "STATE", "BULK", "REASON")
		for _, r := range rows {
			fmt.Printf("%-64s %-7s %-5t %s\n", r.Fingerprint, r.State, r.Bulk, r.Reason)
		}
	case "status":
		r, hosts, err := eng.StatusLane(ctx, rollout.LaneBlocklist)
		if errors.Is(err, rollout.ErrNone) {
			fmt.Println("no blocklist rollout")
			return
		}
		if err != nil {
			fatalf("blocklist status: %v", err)
		}
		converged := 0
		for _, h := range hosts {
			if h.Status == rollout.HostConverged {
				converged++
			}
		}
		fmt.Printf("blocklist rollout v%d: state=%s wave=%d  %d/%d hosts converged\n", r.TargetVersion, r.State, r.ActiveWave, converged, len(hosts))
		for _, h := range hosts {
			fmt.Printf("  %-16s wave=%d %s\n", h.OverlayIP, h.Wave, h.Status)
		}
	default:
		fatalf("blocklist: unknown subcommand %q", sub)
	}
}

// cmdRollout drives staged canary rollouts (6.6). core-api evaluates rollouts on
// every heartbeat; this CLI starts/inspects/forces them for ops and cron.
func cmdRollout(args []string) {
	if len(args) < 1 {
		fatalf("rollout: want start|step|status|abort")
	}
	sub := args[0]
	fs := flag.NewFlagSet("rollout "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	target := fs.Int("target", 0, "target bundle version")
	prev := fs.Int("prev", 1, "previous (stable) bundle version")
	hosts := fs.String("hosts", "", "ordered overlay IPs; the first -canary form the canary wave")
	canary := fs.Int("canary", 1, "canary wave size")
	waveSize := fs.Int("wave-size", 0, "post-canary hosts per wave (0 = all remaining)")
	minHealthy := fs.Int("min-healthy", 0, "healthy-converged required per wave (0 = all in wave)")
	observe := fs.Duration("observe", 10*time.Minute, "wait this long for a wave to converge before judging it stuck")
	missingAfter := fs.Duration("missing-after", 3*time.Minute, "heartbeat silence beyond this => host is down")
	desc := fs.String("desc", "", "rollout description")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	lane := fs.String("lane", "all", "rollout lane (status/step/abort): all|policy|pilot|nebula|blocklist")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	eng := rollout.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "start":
		if *target == 0 || *hosts == "" {
			fatalf("rollout start: -target and -hosts are required")
		}
		r, err := eng.Start(ctx, rollout.StartConfig{
			Description: *desc, TargetVersion: *target, PrevVersion: *prev, Hosts: parseCSV(*hosts),
			CanarySize: *canary, WaveSize: *waveSize, MinHealthy: *minHealthy,
			Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		if err != nil {
			fatalf("rollout start: %v", err)
		}
		fmt.Printf("started rollout #%d: %d -> %d, canary %d of %d host(s)\n", r.ID, *prev, *target, *canary, len(parseCSV(*hosts)))
	case "step":
		changed, err := eng.Evaluate(ctx)
		if err != nil {
			fatalf("rollout step: %v", err)
		}
		printRolloutStatus(ctx, eng, *lane)
		if !changed {
			fmt.Println("(no state change)")
		}
	case "status":
		printRolloutStatus(ctx, eng, *lane)
	case "abort":
		abortLane := *lane
		if abortLane == "all" {
			abortLane = rollout.LanePolicy // abort defaults to the policy lane
		}
		var aerr error
		if abortLane == rollout.LanePolicy {
			aerr = eng.Abort(ctx, *actor)
		} else {
			aerr = eng.AbortLane(ctx, abortLane, *actor)
		}
		if aerr != nil {
			fatalf("rollout abort: %v", aerr)
		}
		fmt.Printf("rollout aborted (lane %s) — touched hosts will revert to prev\n", abortLane)
	default:
		fatalf("rollout: unknown subcommand %q", sub)
	}
}

// printRolloutStatus prints the rollout(s) for the selected lane. lane "all" walks every lane and
// prints each that has a rollout (the default — so a pilot/nebula/blocklist rollout is visible, not
// just the policy lane). A specific lane prints that one, or "[lane] no rollout".
func printRolloutStatus(ctx context.Context, eng *rollout.Engine, lane string) {
	lanes := []string{rollout.LanePolicy, rollout.LaneBlocklist, rollout.LaneNebula, rollout.LanePilot}
	if lane != "all" {
		switch lane {
		case rollout.LanePolicy, rollout.LaneBlocklist, rollout.LaneNebula, rollout.LanePilot:
			lanes = []string{lane}
		default:
			fatalf("rollout: unknown -lane %q (want all|policy|pilot|nebula|blocklist)", lane)
		}
	}
	any := false
	for _, l := range lanes {
		r, hosts, err := eng.StatusLane(ctx, l)
		if errors.Is(err, rollout.ErrNone) {
			if lane != "all" {
				fmt.Printf("[%s] no rollout\n", l)
			}
			continue
		}
		if err != nil {
			fatalf("rollout status (%s): %v", l, err)
		}
		any = true
		fmt.Printf("[%s] rollout #%d: %s  %d -> %d  active_wave=%d\n", l, r.ID, r.State, r.PrevVersion, r.TargetVersion, r.ActiveWave)
		if r.Note != "" {
			fmt.Printf("  note: %s\n", r.Note)
		}
		fmt.Printf("  %-16s %-5s %s\n", "OVERLAY_IP", "WAVE", "STATUS")
		for _, h := range hosts {
			fmt.Printf("  %-16s %-5d %s\n", h.OverlayIP, h.Wave, h.Status)
		}
	}
	if !any && lane == "all" {
		fmt.Println("no rollouts on any lane")
	}
}
