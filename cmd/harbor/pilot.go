package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
)

// Harbor pilot (agent) release management (ADR 0003 Phase 3c): register the
// distributable pilot versions, then stage one across the fleet as a canary rollout on
// the dedicated "pilot" lane — the mirror of `harbor nebula`. core-api stamps each
// host's bundle with its staged generation's (version, sha256, url) tuple and drives
// convergence + auto-rollback on heartbeats; the pilot fetches, verifies, and SELF-
// UPDATES by re-exec/re-adopt (Phase 3b). Pilot self-update is the highest-stakes
// operation — keep the canary small.

func cmdPilot(args []string) {
	if len(args) < 1 {
		fatalf("pilot: want add|add-artifact|list|release|status|abort")
	}
	sub := args[0]
	fs := flag.NewFlagSet("pilot "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	version := fs.String("version", "", "pilot version, e.g. 1.4.0 (add)")
	sha := fs.String("sha256", "", "hex sha256 of the artifact — the integrity anchor (add)")
	file := fs.String("file", "", "local binary to hash for the sha256, instead of -sha256 (add); Harbor still does not host it")
	url := fs.String("url", "", "artifact download URL the pilot fetches; a {version} token is substituted (add)")
	note := fs.String("note", "", "optional note recorded with the release (add)")
	osFlag := fs.String("os", "", "GOOS the artifact is for, e.g. linux|darwin (add/add-artifact); empty -> linux")
	archFlag := fs.String("arch", "", "GOARCH the artifact is for, e.g. amd64|arm64 (add/add-artifact); empty -> amd64")
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
	reg := pilotrelease.New(s.DB)
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	eng := rollout.New(s.DB, audit)

	switch sub {
	case "add":
		rsha, rurl, err := resolveReleaseArgs(*file, *version, *sha, *url)
		if err != nil {
			fatalf("pilot add: %v", err)
		}
		r, err := reg.Add(ctx, *version, *osFlag, *archFlag, rsha, rurl, *note)
		if err != nil {
			fatalf("pilot add: %v", err)
		}
		fmt.Printf("registered pilot %s (%s/%s) as generation %d (sha %s)\n", r.Version, r.GOOS, r.GOARCH, r.Gen, r.SHA256[:12])
		fmt.Printf("  add other platforms: harbor pilot add-artifact -gen %d -os <goos> -arch <goarch> -url ... -sha256 ...\n", r.Gen)
		fmt.Printf("  release it with:     harbor pilot release -gen %d\n", r.Gen)
		if !*skipURLCheck {
			reportReleaseURL(ctx, *file, rurl)
		}
	case "add-artifact":
		if *gen == 0 {
			fatalf("pilot add-artifact: -gen is required (see `harbor pilot list`)")
		}
		if *osFlag == "" || *archFlag == "" {
			fatalf("pilot add-artifact: -os and -arch are required")
		}
		rel, ok := reg.Get(ctx, *gen)
		if !ok {
			fatalf("pilot add-artifact: no such generation %d (see `harbor pilot list`)", *gen)
		}
		rsha, rurl, err := resolveReleaseArgs(*file, rel.Version, *sha, *url)
		if err != nil {
			fatalf("pilot add-artifact: %v", err)
		}
		a, err := reg.AddArtifact(ctx, *gen, *osFlag, *archFlag, rsha, rurl)
		if err != nil {
			fatalf("pilot add-artifact: %v", err)
		}
		fmt.Printf("registered pilot %s %s/%s for generation %d (sha %s)\n", rel.Version, a.GOOS, a.GOARCH, *gen, a.SHA256[:12])
		if !*skipURLCheck {
			reportReleaseURL(ctx, *file, rurl)
		}
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("pilot list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no pilot releases registered")
			return
		}
		cur := eng.CurrentPilotGen(ctx)
		fmt.Printf("%-4s %-12s %-11s %-13s %-14s %s\n", "GEN", "VERSION", "STATUS", "PLATFORM", "SHA256", "URL")
		for _, r := range rows {
			status := r.Status
			if int(r.Gen) == cur {
				status = pilotrelease.StatusCurrent
			}
			fmt.Printf("%-4d %-12s %-11s %-13s %-14s %s\n", r.Gen, r.Version, status, r.GOOS+"/"+r.GOARCH, r.SHA256[:12], r.URL)
			arts, _ := reg.Artifacts(ctx, int(r.Gen)) // per-arch artifacts, indented under their generation
			for _, a := range arts {
				fmt.Printf("%-4s %-12s %-11s %-13s %-14s %s\n", "", "", "", a.GOOS+"/"+a.GOARCH, a.SHA256[:12], a.URL)
			}
		}
	case "release":
		if *gen == 0 {
			fatalf("pilot release: -gen is required (see `harbor pilot list`)")
		}
		rel, ok := reg.Get(ctx, *gen)
		if !ok {
			fatalf("pilot release: no such generation %d (see `harbor pilot list`)", *gen)
		}
		var ips []string
		if err := s.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
			fatalf("pilot release: read fleet: %v", err)
		}
		// Arch affinity: only stage hosts whose arch this generation actually ships (see nebula release).
		servable, excluded, err := reg.ServableFleet(ctx, *gen, ips)
		if err != nil {
			fatalf("pilot release: %v", err)
		}
		if len(excluded) > 0 {
			fmt.Printf("note: %d of %d host(s) excluded — gen %d ships no artifact for their arch:\n", len(excluded), len(ips), *gen)
			for _, h := range excluded {
				fmt.Printf("  %-18s %s/%s\n", h.OverlayIP, h.GOOS, h.GOARCH)
			}
			fmt.Printf("  add their arch then re-release: harbor pilot add-artifact -gen %d -os <goos> -arch <goarch> -url ... -sha256 ...\n", *gen)
		}
		if len(ips) > 0 && len(servable) == 0 {
			fmt.Printf("no hosts can run gen %d — all %d live host(s) are an arch this generation does not ship; register their arch first\n", *gen, len(ips))
			return
		}
		prev := eng.CurrentPilotGen(ctx)
		r, err := eng.Start(ctx, rollout.StartConfig{
			Lane: rollout.LanePilot, Description: fmt.Sprintf("pilot %s (gen %d)", rel.Version, rel.Gen),
			TargetVersion: *gen, PrevVersion: prev, Hosts: servable,
			CanarySize: *canary, WaveSize: *waveSize, Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		switch {
		case errors.Is(err, rollout.ErrNoHosts):
			fmt.Println("note: no fleet heartbeats yet — new hosts enroll on the current version; no rollout started")
		case errors.Is(err, rollout.ErrActiveExists):
			fmt.Println("note: a pilot rollout is already in flight — finish it or `harbor pilot abort` first")
		case err != nil:
			fatalf("pilot release: %v", err)
		default:
			fmt.Printf("staged pilot %s (gen %d over %d) to %d host(s), canary %d; core-api drives convergence on heartbeats\n",
				rel.Version, *gen, prev, len(servable), min(*canary, len(servable)))
			_ = r
		}
	case "status":
		r, hosts, err := eng.StatusLane(ctx, rollout.LanePilot)
		if errors.Is(err, rollout.ErrNone) {
			fmt.Println("no pilot rollout")
			return
		}
		if err != nil {
			fatalf("pilot status: %v", err)
		}
		converged := 0
		for _, h := range hosts {
			if h.Status == rollout.HostConverged {
				converged++
			}
		}
		fmt.Printf("pilot rollout gen %d (over %d): state=%s wave=%d  %d/%d hosts converged\n",
			r.TargetVersion, r.PrevVersion, r.State, r.ActiveWave, converged, len(hosts))
		if r.Note != "" {
			fmt.Printf("  note: %s\n", r.Note)
		}
		for _, h := range hosts {
			fmt.Printf("  %-16s wave=%d %s\n", h.OverlayIP, h.Wave, h.Status)
		}
	case "abort":
		if err := eng.AbortLane(ctx, rollout.LanePilot, *actor); err != nil {
			fatalf("pilot abort: %v", err)
		}
		fmt.Println("pilot rollout aborted — touched hosts revert to the previous generation")
	default:
		fatalf("pilot: unknown subcommand %q", sub)
	}
}
