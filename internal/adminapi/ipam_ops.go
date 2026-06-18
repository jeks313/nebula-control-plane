package adminapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"

	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
)

// This file holds the ADR-0010 Phase-3 IPAM admin surface: netblock CRUD +
// growth-aware placement suggestions + per-block allocation/overlay data. It
// follows the join-key/lighthouse pattern — identity -> requirePerm -> service
// call -> problem+json mapping -> audit on mutations (+ requireStepUp, since
// carving address space is sensitive per IPAM-DECISIONS D5). The GET endpoints
// are read-only and carry no perm gate (viewer included), like the other reads.

// ── views ─────────────────────────────────────────────────────────────────

// NetblockView is the API view of a netblock plus its computed utilization.
type NetblockView struct {
	Name        string  `json:"name"`
	CIDR        string  `json:"cidr"`
	Kind        string  `json:"kind"`
	Description string  `json:"description,omitempty"`
	Protected   bool    `json:"protected"`
	Capacity    int64   `json:"capacity"`  // usable host count (minus the network address)
	Allocated   int     `json:"allocated"` // current allocations inside the CIDR
	Used        int     `json:"used"`      // live (heartbeat within the fleet stale window) ⊆ allocated
	Pct         float64 `json:"pct"`       // allocated/capacity * 100 (one decimal)
	CreatedAt   string  `json:"created_at"`
	CreatedBy   string  `json:"created_by,omitempty"`
}

// AllocationView is one allocation inside a netblock (overlay/heat data).
type AllocationView struct {
	IP          string `json:"ip"`
	Device      string `json:"device,omitempty"`
	Method      string `json:"method,omitempty"`
	AllocatedAt string `json:"allocated_at,omitempty"`
}

// netblockHostCapacity is the usable host count of an IPv4 CIDR: 2^(32-bits)
// minus the network base address (which is never handed out). Mirrors
// ipam.hostCapacity (unexported there) so utilization matches the allocator.
func netblockHostCapacity(p netip.Prefix) int64 {
	bits := p.Bits()
	if !p.IsValid() || bits < 0 || bits > 32 {
		return 0
	}
	total := int64(1) << uint(32-bits)
	if total <= 1 {
		return 0
	}
	return total - 1
}

func pctOf(allocated int, capacity int64) float64 {
	if capacity <= 0 {
		return 0
	}
	v := float64(allocated) / float64(capacity) * 100
	return math.Round(v*10) / 10 // one decimal place
}

// mapNetblockErr maps netblock domain sentinels to problem+json; unknown errors
// are 500 (logged).
func (s *Server) mapNetblockErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, netblock.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not found", "no such netblock")
	case errors.Is(err, netblock.ErrExists):
		writeProblem(w, http.StatusConflict, "already exists", "a netblock with that name already exists")
	case errors.Is(err, netblock.ErrOverlap):
		writeProblem(w, http.StatusConflict, "overlap", "the CIDR overlaps an existing netblock or reservation")
	case errors.Is(err, netblock.ErrProtected):
		writeProblem(w, http.StatusConflict, "protected", "this netblock is protected (seeded at genesis) and cannot be edited or removed")
	case errors.Is(err, netblock.ErrStranded):
		// Well-formed request that cannot be applied against live state — the same
		// 422 convention used for a dual-control commit failure.
		writeProblem(w, http.StatusUnprocessableEntity, "would strand allocations", "the new range would strand live allocations; reclaim those hosts first")
	case errors.Is(err, netblock.ErrPoolFull):
		writeProblem(w, http.StatusConflict, "pool full", "no aligned slot of that size is available in the pool")
	case errors.Is(err, netblock.ErrBadCIDR), errors.Is(err, netblock.ErrOutOfPool),
		errors.Is(err, netblock.ErrNoName), errors.Is(err, netblock.ErrReservedKind),
		errors.Is(err, netblock.ErrBadPrefixLen):
		writeProblem(w, http.StatusBadRequest, "invalid netblock", err.Error())
	default:
		s.fail(w, r, "netblock operation failed", err)
	}
}

// ipamConfigured reports whether the IPAM engines are wired; if not it writes a
// 503 (matching the "not configured" semantics) and returns false.
func (s *Server) ipamConfigured(w http.ResponseWriter) bool {
	if s.cfg.Netblocks == nil {
		writeProblem(w, http.StatusServiceUnavailable, "ipam not configured", "the netblock registry is not wired on this server")
		return false
	}
	return true
}

// ── netblocks ───────────────────────────────────────────────────────────────

// GET /admin/v1/ipam/netblocks — list netblocks with per-block utilization. The
// configured pool prefix rides along as a top-level `pool` so the UI overlay can show
// free space above the highest block (it no longer has to derive the extent from the
// block list — D21 supersedes the D19 workaround).
func (s *Server) handleNetblocks(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Netblocks == nil {
		writeJSON(w, http.StatusOK, map[string]any{"netblocks": []NetblockView{}, "count": 0, "pool": s.poolString()})
		return
	}
	ctx := r.Context()
	rows, err := s.cfg.Netblocks.List(ctx)
	if err != nil {
		s.fail(w, r, "list netblocks failed", err)
		return
	}
	// One pluck of every live allocation IP; bucket per-CIDR in Go (the fleet is
	// small, the netblock set tiny — central/default + a few carves).
	allocIPs, err := s.allocationIPs(ctx)
	if err != nil {
		s.fail(w, r, "load allocations failed", err)
		return
	}
	// One pluck of the FRESH overlay IPs (heartbeat within the fleet stale window): an
	// allocation is "used" iff its IP is in this set. Same window the fleet uses, so
	// "used" agrees with the fleet's "stale" verdict (D23). `used` ⊆ `allocated`.
	fresh, err := s.freshOverlayIPs(ctx)
	if err != nil {
		s.fail(w, r, "load heartbeats failed", err)
		return
	}
	out := make([]NetblockView, len(rows))
	for i, row := range rows {
		p := row.Prefix()
		capacity := netblockHostCapacity(p)
		allocated, used := 0, 0
		for _, a := range allocIPs {
			if p.IsValid() && p.Contains(a) {
				allocated++
				if fresh[a] {
					used++
				}
			}
		}
		out[i] = NetblockView{
			Name: row.Name, CIDR: row.CIDR, Kind: row.Kind, Description: row.Description,
			Protected: row.Protected, Capacity: capacity, Allocated: allocated, Used: used,
			Pct: pctOf(allocated, capacity), CreatedAt: rfc3339(row.CreatedAt), CreatedBy: row.CreatedBy,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"netblocks": out, "count": len(out), "pool": s.poolString()})
}

// poolString renders the configured overlay pool prefix for the list response, or ""
// if no pool is configured (the UI then falls back to the block-derived extent).
func (s *Server) poolString() string {
	if s.cfg.Pool.IsValid() {
		return s.cfg.Pool.String()
	}
	return ""
}

// POST /admin/v1/ipam/netblocks — carve a new named netblock.
func (s *Server) handleNetblockCreate(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermIPAMManage) {
		return
	}
	if !s.requireStepUp(w, id) { // carving address space is sensitive (D5)
		return
	}
	if !s.ipamConfigured(w) {
		return
	}
	var b struct {
		Name        string `json:"name"`
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.Name == "" {
		writeProblem(w, http.StatusBadRequest, "name required", "the 'name' field is empty")
		return
	}
	cidr, perr := netip.ParsePrefix(b.CIDR)
	if perr != nil {
		writeProblem(w, http.StatusBadRequest, "invalid cidr", "the 'cidr' field is not a valid IPv4 prefix (e.g. 10.44.20.0/24)")
		return
	}
	row, err := s.cfg.Netblocks.Add(r.Context(), b.Name, cidr, b.Description, id.Principal)
	if err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "netblock-create", row.Name,
		fmt.Sprintf("cidr=%s", row.CIDR))
	writeJSON(w, http.StatusCreated, s.netblockView(r.Context(), row))
}

// PATCH /admin/v1/ipam/netblocks/{name} — edit a netblock's CIDR/description. An
// omitted cidr keeps the current one (so a description-only edit never trips the
// stranding guard); the registry blocks edits that would strand live allocations.
func (s *Server) handleNetblockUpdate(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermIPAMManage) {
		return
	}
	if !s.requireStepUp(w, id) {
		return
	}
	if !s.ipamConfigured(w) {
		return
	}
	name := r.PathValue("name")
	var b struct {
		CIDR        *string `json:"cidr"`
		Description *string `json:"description"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	// Load the current row so an omitted cidr/description leaves it unchanged.
	cur, err := s.cfg.Netblocks.Get(r.Context(), name)
	if err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	cidr := cur.Prefix()
	if b.CIDR != nil {
		c, perr := netip.ParsePrefix(*b.CIDR)
		if perr != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cidr", "the 'cidr' field is not a valid IPv4 prefix")
			return
		}
		cidr = c
	}
	description := cur.Description
	if b.Description != nil {
		description = *b.Description
	}
	row, err := s.cfg.Netblocks.Update(r.Context(), name, cidr, description, id.Principal)
	if err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "netblock-update", row.Name,
		fmt.Sprintf("cidr=%s", row.CIDR))
	writeJSON(w, http.StatusOK, s.netblockView(r.Context(), row))
}

// DELETE /admin/v1/ipam/netblocks/{name} — remove a netblock (protected/in-use
// blocks are refused by the registry).
func (s *Server) handleNetblockRemove(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermIPAMManage) {
		return
	}
	if !s.requireStepUp(w, id) {
		return
	}
	if !s.ipamConfigured(w) {
		return
	}
	name := r.PathValue("name")
	if err := s.cfg.Netblocks.Remove(r.Context(), name, id.Principal); err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "netblock-remove", name, "")
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "removed": true})
}

// GET /admin/v1/ipam/netblocks/suggest?prefix=N — the growth-aware placement
// suggestion for a new /N netblock (read-only; ungated like the analysis endpoints).
func (s *Server) handleNetblockSuggest(w http.ResponseWriter, r *http.Request) {
	if !s.ipamConfigured(w) {
		return
	}
	prefix := queryInt(r, "prefix", 0, 0, 32)
	if r.URL.Query().Get("prefix") == "" || prefix == 0 {
		writeProblem(w, http.StatusBadRequest, "prefix required", "the 'prefix' query parameter (a prefix length 1-32) is required")
		return
	}
	p, err := s.cfg.Netblocks.Suggest(r.Context(), prefix)
	if err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefix": prefix, "cidr": p.String()})
}

// GET /admin/v1/ipam/allocations?netblock=NAME — allocations within a netblock
// (overlay/heat data). netblock is required; read-only, ungated.
func (s *Server) handleIPAMAllocations(w http.ResponseWriter, r *http.Request) {
	if !s.ipamConfigured(w) {
		return
	}
	name := r.URL.Query().Get("netblock")
	if name == "" {
		writeProblem(w, http.StatusBadRequest, "netblock required", "the 'netblock' query parameter (a netblock name) is required")
		return
	}
	ctx := r.Context()
	row, err := s.cfg.Netblocks.Get(ctx, name)
	if err != nil {
		s.mapNetblockErr(w, r, err)
		return
	}
	p := row.Prefix()
	rows, err := s.allocationsIn(ctx, p)
	if err != nil {
		s.fail(w, r, "list allocations failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"netblock": name, "cidr": row.CIDR, "allocations": rows, "count": len(rows)})
}

// ── store reads ──────────────────────────────────────────────────────────────

// allocationIPs plucks every allocation IP (live or quarantined) for the
// utilization bucketing.
func (s *Server) allocationIPs(ctx context.Context) ([]netip.Addr, error) {
	var ips []string
	if err := s.cfg.Store.DB.WithContext(ctx).Model(&ipam.Allocation{}).Pluck("ip", &ips).Error; err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, str := range ips {
		if a, err := netip.ParseAddr(str); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// freshOverlayIPs plucks the overlay IPs whose heartbeat is within the fleet stale
// window (last_seen >= now - StaleAfter) — the fleet's "not stale" set. An allocation
// is "used" (live) iff its IP is in this set; this uses the SAME window the fleet uses
// for its stale verdict (s.cfg.Thresholds.StaleAfter, defaulted to 5m in New), so
// "used" and "stale" never disagree (D23). The heartbeats table is keyed by overlay_ip
// (= the allocated IP), so this joins directly to allocations with no device hop.
func (s *Server) freshOverlayIPs(ctx context.Context) (map[netip.Addr]bool, error) {
	cutoff := s.now().UnixNano() - s.cfg.Thresholds.StaleAfter.Nanoseconds()
	var ips []string
	if err := s.cfg.Store.DB.WithContext(ctx).
		Table("heartbeats").
		Where("last_seen >= ?", cutoff).
		Pluck("overlay_ip", &ips).Error; err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]bool, len(ips))
	for _, str := range ips {
		if a, err := netip.ParseAddr(str); err == nil {
			out[a] = true
		}
	}
	return out, nil
}

// allocRow is a join of ip_allocations + the device name, for the allocations view.
type allocRow struct {
	IP          string `gorm:"column:ip"`
	Method      string `gorm:"column:method"`
	AllocatedAt int64  `gorm:"column:allocated_at"`
	Device      string `gorm:"column:device"`
}

// allocationsIn returns every allocation whose IP falls inside rng, with the
// device name joined in. Loads all allocations and filters by CIDR in Go (the
// IP column is TEXT, so a CIDR predicate isn't expressible in portable SQL).
func (s *Server) allocationsIn(ctx context.Context, rng netip.Prefix) ([]AllocationView, error) {
	var rows []allocRow
	err := s.cfg.Store.DB.WithContext(ctx).
		Table("ip_allocations AS a").
		Select("a.ip AS ip, a.method AS method, a.allocated_at AS allocated_at, d.name AS device").
		Joins("LEFT JOIN devices d ON d.id = a.device_id").
		Order("a.ip ASC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]AllocationView, 0, len(rows))
	for _, row := range rows {
		a, perr := netip.ParseAddr(row.IP)
		if perr != nil || !rng.IsValid() || !rng.Contains(a) {
			continue
		}
		out = append(out, AllocationView{
			IP: row.IP, Device: row.Device, Method: row.Method, AllocatedAt: rfc3339(row.AllocatedAt),
		})
	}
	return out, nil
}

// netblockView builds the single-row view (used by create/update responses),
// computing utilization against the live allocations + fresh heartbeats. `used` (live,
// heartbeat within the fleet stale window) ⊆ `allocated` (D23).
func (s *Server) netblockView(ctx context.Context, row netblock.Netblock) NetblockView {
	p := row.Prefix()
	capacity := netblockHostCapacity(p)
	allocated, used := 0, 0
	if ips, err := s.allocationIPs(ctx); err == nil {
		fresh, _ := s.freshOverlayIPs(ctx) // best-effort; a heartbeat read error leaves used=0
		for _, a := range ips {
			if p.IsValid() && p.Contains(a) {
				allocated++
				if fresh[a] {
					used++
				}
			}
		}
	}
	return NetblockView{
		Name: row.Name, CIDR: row.CIDR, Kind: row.Kind, Description: row.Description,
		Protected: row.Protected, Capacity: capacity, Allocated: allocated, Used: used,
		Pct: pctOf(allocated, capacity), CreatedAt: rfc3339(row.CreatedAt), CreatedBy: row.CreatedBy,
	}
}
