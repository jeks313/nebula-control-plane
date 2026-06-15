package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
)

// Harbor nebula data-plane release management (ADR 0003 Phase 1c): register the
// distributable nebula versions (the registry), then stage one across the fleet as a
// canary rollout on the dedicated "nebula" lane. core-api stamps each host's bundle
// with its staged generation's (version, sha256, url) tuple and drives convergence +
// auto-rollback on heartbeats; the pilot fetches, verifies, and swaps the binary.

func cmdNebula(args []string) {
	if len(args) < 1 {
		fatalf("nebula: want add|list|release|status|abort")
	}
	sub := args[0]
	fs := flag.NewFlagSet("nebula "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	version := fs.String("version", "", "nebula version, e.g. 1.10.3 (add)")
	sha := fs.String("sha256", "", "hex sha256 of the artifact — the integrity anchor (add)")
	file := fs.String("file", "", "local binary to hash for the sha256, instead of -sha256 (add); Harbor still does not host it")
	url := fs.String("url", "", "artifact download URL the pilot fetches; a {version} token is substituted (add)")
	note := fs.String("note", "", "optional note recorded with the release (add)")
	skipURLCheck := fs.Bool("skip-url-check", false, "skip the best-effort reachability HEAD on -url at add time (air-gapped admin host)")
	gen := fs.Int("gen", 0, "generation to release (release)")
	canary := fs.Int("canary", 1, "canary wave size (release)")
	waveSize := fs.Int("wave-size", 0, "post-canary hosts per wave; 0 = all remaining (release)")
	observe := fs.Duration("observe", 10*time.Minute, "per-wave convergence window before judging it stuck (release)")
	missingAfter := fs.Duration("missing-after", 3*time.Minute, "heartbeat silence => host considered down (release)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	reg := nebularelease.New(s.DB)
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	eng := rollout.New(s.DB, audit)

	switch sub {
	case "add":
		rsha, rurl, err := resolveReleaseArgs(*file, *version, *sha, *url)
		if err != nil {
			fatalf("nebula add: %v", err)
		}
		r, err := reg.Add(ctx, *version, rsha, rurl, *note)
		if err != nil {
			fatalf("nebula add: %v", err)
		}
		fmt.Printf("registered nebula %s as generation %d (sha %s)\n", r.Version, r.Gen, r.SHA256[:12])
		fmt.Printf("  release it with: harbor nebula release -gen %d\n", r.Gen)
		if !*skipURLCheck {
			reportReleaseURL(ctx, *file, rurl)
		}
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("nebula list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no nebula releases registered")
			return
		}
		cur := eng.CurrentNebulaGen(ctx) // the live fleet-desired generation
		fmt.Printf("%-4s %-12s %-11s %-14s %s\n", "GEN", "VERSION", "STATUS", "SHA256", "URL")
		for _, r := range rows {
			status := r.Status
			if int(r.Gen) == cur {
				status = nebularelease.StatusCurrent
			}
			fmt.Printf("%-4d %-12s %-11s %-14s %s\n", r.Gen, r.Version, status, r.SHA256[:12], r.URL)
		}
	case "release":
		if *gen == 0 {
			fatalf("nebula release: -gen is required (see `harbor nebula list`)")
		}
		rel, ok := reg.Get(ctx, *gen)
		if !ok {
			fatalf("nebula release: no such generation %d (see `harbor nebula list`)", *gen)
		}
		var ips []string
		if err := s.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
			fatalf("nebula release: read fleet: %v", err)
		}
		prev := eng.CurrentNebulaGen(ctx) // fleet falls back to this on rollback
		r, err := eng.Start(ctx, rollout.StartConfig{
			Lane: rollout.LaneNebula, Description: fmt.Sprintf("nebula %s (gen %d)", rel.Version, rel.Gen),
			TargetVersion: *gen, PrevVersion: prev, Hosts: ips,
			CanarySize: *canary, WaveSize: *waveSize, Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		switch {
		case errors.Is(err, rollout.ErrNoHosts):
			fmt.Println("note: no fleet heartbeats yet — new hosts enroll on the current version; no rollout started")
		case errors.Is(err, rollout.ErrActiveExists):
			fmt.Println("note: a nebula rollout is already in flight — finish it or `harbor nebula abort` first")
		case err != nil:
			fatalf("nebula release: %v", err)
		default:
			fmt.Printf("staged nebula %s (gen %d over %d) to %d host(s), canary %d; core-api drives convergence on heartbeats\n",
				rel.Version, *gen, prev, len(ips), *canary)
			_ = r
		}
	case "status":
		r, hosts, err := eng.StatusLane(ctx, rollout.LaneNebula)
		if errors.Is(err, rollout.ErrNone) {
			fmt.Println("no nebula rollout")
			return
		}
		if err != nil {
			fatalf("nebula status: %v", err)
		}
		converged := 0
		for _, h := range hosts {
			if h.Status == rollout.HostConverged {
				converged++
			}
		}
		fmt.Printf("nebula rollout gen %d (over %d): state=%s wave=%d  %d/%d hosts converged\n",
			r.TargetVersion, r.PrevVersion, r.State, r.ActiveWave, converged, len(hosts))
		if r.Note != "" {
			fmt.Printf("  note: %s\n", r.Note)
		}
		for _, h := range hosts {
			fmt.Printf("  %-16s wave=%d %s\n", h.OverlayIP, h.Wave, h.Status)
		}
	case "abort":
		if err := eng.AbortLane(ctx, rollout.LaneNebula, *actor); err != nil {
			fatalf("nebula abort: %v", err)
		}
		fmt.Println("nebula rollout aborted — touched hosts revert to the previous generation")
	default:
		fatalf("nebula: unknown subcommand %q", sub)
	}
}
