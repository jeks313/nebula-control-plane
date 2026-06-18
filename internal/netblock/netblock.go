// Package netblock manages named, non-overlapping CIDRs ("netblocks") carved from
// the mesh pool (ADR 0010 — IPAM). It is the single source of truth for the
// fleet's address-space layout: each join source (join-key row, cloud-trust
// scope, future SSO entry) references a netblock by NAME, and the allocator
// resolves name -> CIDR and fills sequentially within it, so related hosts
// cluster by join source.
//
// Three kinds exist:
//   - reserved — control-plane space. 'central' is seeded at genesis (lighthouse,
//     core, backend headroom); protected from deletion.
//   - default  — the bounded fallback an unbound join method draws from; seeded at
//     genesis, operator-sized, protected.
//   - named    — admin-carved via the IPAM UI, each bindable to join sources.
//
// The Registry mirrors lighthouse.Registry (Add/Update/Remove/List + audit hook),
// enforcing: a valid IPv4 CIDR inside the pool, non-overlap with every other
// netblock (and the pool's reservations), and — on remove/edit — that the block is
// not protected and strands no live allocations. Suggest is the growth-aware
// placement function shared by the create UI and the server-side default.
package netblock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"gorm.io/gorm"
)

// Kinds.
const (
	KindReserved = "reserved" // control-plane (central)
	KindDefault  = "default"  // the bounded fallback
	KindNamed    = "named"    // admin-carved, bindable to join sources
)

// Reserved netblock names seeded at genesis.
const (
	NameCentral = "central"
	NameDefault = "default"
)

// Growth-envelope tunables (ADR 0010 — "Growth-aware placement"). A /27 request
// soft-claims a /24 envelope (8x headroom) with the defaults below.
const (
	// MarginBits widens the requested /P up to a coarser /E = P-MarginBits growth
	// envelope; Suggest places a fresh block at the START of the first wholly-free
	// envelope so it can grow in place without relocating a live allocation.
	MarginBits = 3
	// EnvelopeFloor caps how coarse an envelope may get (a /24 by default), so a
	// large request doesn't soft-claim an unreasonably large region.
	EnvelopeFloor = 24
)

// Errors callers can branch on.
var (
	ErrNotFound     = errors.New("netblock: not found")
	ErrExists       = errors.New("netblock: a netblock with that name already exists")
	ErrNoName       = errors.New("netblock: a name is required")
	ErrBadCIDR      = errors.New("netblock: CIDR is not a valid IPv4 prefix")
	ErrOutOfPool    = errors.New("netblock: CIDR is not inside the mesh pool")
	ErrOverlap      = errors.New("netblock: CIDR overlaps an existing netblock or reservation")
	ErrProtected    = errors.New("netblock: protected netblock cannot be modified or removed")
	ErrStranded     = errors.New("netblock: edit/remove would strand live allocations outside the new range")
	ErrPoolFull     = errors.New("netblock: pool full for this size — no aligned slot available")
	ErrBadPrefixLen = errors.New("netblock: requested prefix length is out of range for the pool")
	ErrReservedKind = errors.New("netblock: reserved/default kinds are seeded at genesis, not created via Add")
)

// Netblock is a stored netblock row.
type Netblock struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Name        string `gorm:"column:name"`
	CIDR        string `gorm:"column:cidr"`
	Kind        string `gorm:"column:kind"`
	Description string `gorm:"column:description"`
	Protected   bool   `gorm:"column:protected"`
	CreatedAt   int64  `gorm:"column:created_at"`
	CreatedBy   string `gorm:"column:created_by"`
}

// TableName pins the table.
func (Netblock) TableName() string { return "netblocks" }

// Prefix parses the stored CIDR. The zero Prefix is returned on a malformed value
// (which the registry's validation prevents from ever being persisted).
func (n Netblock) Prefix() netip.Prefix {
	p, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return netip.Prefix{}
	}
	return p.Masked()
}

// AuditFunc appends one row to the hash-chained audit log (matches
// lighthouse.AuditFunc so the same wiring serves both).
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// allocationLister loads the live (allocated or quarantined) addresses, used by
// the registry's stranding guard. *ipam.Allocator is wired in by the caller, but
// the registry depends only on this minimal interface to avoid an import cycle.
type allocationLister interface {
	LiveAddrs(ctx context.Context) ([]netip.Addr, error)
}

// Registry manages the netblock set inside a fixed mesh pool.
type Registry struct {
	db       *gorm.DB
	pool     netip.Prefix
	reserved []netip.Addr // pool reservations (never carve-able; e.g. structural)
	allocs   allocationLister
	audit    AuditFunc
	now      func() time.Time
	log      *slog.Logger

	mu    sync.Mutex
	cache *resolverCache // lazily built; invalidated on every mutation
	gen   uint64         // bumped on every invalidate so a stale snapshot can't overwrite a fresh cache
}

// New builds a Registry over pool. reserved are addresses that may not be carved
// over (typically none — central holds the lighthouse/core IPs as a netblock).
// allocs (optional) backs the stranding guard; nil disables it (CLI/tests with no
// live allocations). audit (optional) records mutations.
func New(db *gorm.DB, pool netip.Prefix, reserved []netip.Addr, allocs allocationLister, audit AuditFunc) *Registry {
	return &Registry{
		db:       db,
		pool:     pool.Masked(),
		reserved: append([]netip.Addr(nil), reserved...),
		allocs:   allocs,
		audit:    audit,
		now:      time.Now,
		log:      slog.Default(),
	}
}

// List returns every netblock, newest first.
func (r *Registry) List(ctx context.Context) ([]Netblock, error) {
	var rows []Netblock
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("netblock: list: %w", err)
	}
	return rows, nil
}

// Get returns a netblock by name.
func (r *Registry) Get(ctx context.Context, name string) (Netblock, error) {
	var row Netblock
	err := r.db.WithContext(ctx).First(&row, "name = ?", name).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Netblock{}, ErrNotFound
	}
	if err != nil {
		return Netblock{}, fmt.Errorf("netblock: get: %w", err)
	}
	return row, nil
}

// Add carves a new 'named' netblock. cidr must be a valid IPv4 prefix inside the
// pool that overlaps no existing netblock or reservation.
func (r *Registry) Add(ctx context.Context, name string, cidr netip.Prefix, description, actor string) (Netblock, error) {
	if name == "" {
		return Netblock{}, ErrNoName
	}
	if name == NameCentral || name == NameDefault {
		return Netblock{}, ErrReservedKind
	}
	if err := r.validateCIDR(ctx, cidr, ""); err != nil {
		return Netblock{}, err
	}
	now := r.now().UTC().UnixNano()
	row := Netblock{
		Name: name, CIDR: cidr.Masked().String(), Kind: KindNamed,
		Description: description, Protected: false, CreatedAt: now, CreatedBy: actor,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return Netblock{}, ErrExists
		}
		return Netblock{}, fmt.Errorf("netblock: add: %w", err)
	}
	r.invalidate()
	// Note: admin CRUD is audited by the handler (it carries the principal). The
	// registry deliberately does NOT audit Add/Update/Remove to avoid a double entry;
	// only Grow (auto-grow, no handler/principal) is audited here.
	return row, nil
}

// Seed inserts a protected genesis netblock (central/default). It is idempotent on
// the name: a re-genesis over an existing row is a no-op returning the existing
// row. Unlike Add it accepts the reserved/default kinds and bypasses the
// non-reserved-name guard, but still enforces in-pool + non-overlap.
func (r *Registry) Seed(ctx context.Context, name string, cidr netip.Prefix, kind, description, actor string) (Netblock, error) {
	if name == "" {
		return Netblock{}, ErrNoName
	}
	if kind != KindReserved && kind != KindDefault {
		return Netblock{}, fmt.Errorf("netblock: seed: kind must be %q or %q", KindReserved, KindDefault)
	}
	if existing, err := r.Get(ctx, name); err == nil {
		return existing, nil // idempotent: already seeded
	} else if !errors.Is(err, ErrNotFound) {
		return Netblock{}, err
	}
	if err := r.validateCIDR(ctx, cidr, ""); err != nil {
		return Netblock{}, err
	}
	now := r.now().UTC().UnixNano()
	row := Netblock{
		Name: name, CIDR: cidr.Masked().String(), Kind: kind,
		Description: description, Protected: true, CreatedAt: now, CreatedBy: actor,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return r.Get(ctx, name)
		}
		return Netblock{}, fmt.Errorf("netblock: seed: %w", err)
	}
	r.invalidate()
	r.recordAudit(ctx, actor, "netblock-seed", name, fmt.Sprintf(`{"cidr":%q,"kind":%q}`, row.CIDR, kind))
	return row, nil
}

// Update edits a netblock's CIDR and/or description in place. A protected netblock
// (central/default) may not be edited. A CIDR change is rejected if it would
// strand any live allocation outside the new range, or if it overlaps another
// netblock/reservation.
//
// All reads (validation + stranding) run BEFORE the write rather than inside one
// transaction: SQLite's single writer connection (SetMaxOpenConns(1)) deadlocks a
// nested read on r.db while a transaction is open. The CIDR-conditional UPDATE
// below is the atomicity guard — a concurrent edit changes the CIDR, so the write
// affects 0 rows and we report the lost race.
func (r *Registry) Update(ctx context.Context, name string, cidr netip.Prefix, description, actor string) (Netblock, error) {
	row, err := r.Get(ctx, name)
	if err != nil {
		return Netblock{}, err
	}
	if row.Protected {
		return Netblock{}, ErrProtected
	}
	if err := r.validateCIDR(ctx, cidr, name); err != nil {
		return Netblock{}, err
	}
	// Stranding guard: every live allocation inside the OLD range must still be
	// inside the NEW range.
	if err := r.checkNoStranded(ctx, row.Prefix(), cidr.Masked()); err != nil {
		return Netblock{}, err
	}
	oldCIDR := row.Prefix().String()
	newCIDR := cidr.Masked().String()
	res := r.db.WithContext(ctx).Model(&Netblock{}).
		Where("name = ? AND cidr = ?", name, oldCIDR).
		Updates(map[string]any{"cidr": newCIDR, "description": description})
	if res.Error != nil {
		return Netblock{}, fmt.Errorf("netblock: update: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return Netblock{}, ErrNotFound // row vanished or its CIDR changed under us
	}
	r.invalidate()
	// Admin CRUD is audited by the handler (see Add).
	row.CIDR = newCIDR
	row.Description = description
	return row, nil
}

// Remove deletes a netblock. Protected blocks (central/default) refuse removal, as
// does any block with live allocations inside it. Reads run before the delete (the
// SQLite single-writer deadlock note on Update applies).
func (r *Registry) Remove(ctx context.Context, name, actor string) error {
	row, err := r.Get(ctx, name)
	if err != nil {
		return err
	}
	if row.Protected {
		return ErrProtected
	}
	// Any live allocation inside the block strands on removal.
	if err := r.checkNoStranded(ctx, row.Prefix(), netip.Prefix{}); err != nil {
		return err
	}
	if err := r.db.WithContext(ctx).Where("name = ?", name).Delete(&Netblock{}).Error; err != nil {
		return fmt.Errorf("netblock: remove: %w", err)
	}
	r.invalidate()
	// Admin CRUD is audited by the handler (see Add).
	return nil
}

// Grow extends a 'named' netblock by one doubling (/P -> /P-1) keeping its network
// address (start-of-envelope placement guarantees the buddy is the upper half), if
// that buddy is wholly free of reservations, carves, and live allocations. Returns
// the new prefix, or ErrPoolFull when the buddy is occupied / a grow isn't possible.
//
// The grow is made atomic by the CIDR-conditional UPDATE (WHERE cidr = oldCIDR):
// two racing growers serialize on it — the loser sees RowsAffected == 0 and
// re-reads. (Reads run before the write, not inside a transaction, for the SQLite
// single-writer reason noted on Update.)
func (r *Registry) Grow(ctx context.Context, name, actor string) (netip.Prefix, error) {
	row, err := r.Get(ctx, name)
	if err != nil {
		return netip.Prefix{}, err
	}
	if row.Kind != KindNamed {
		return netip.Prefix{}, fmt.Errorf("netblock: grow: only named netblocks auto-grow (%q is %q)", name, row.Kind)
	}
	cur := row.Prefix()
	if cur.Bits() <= 0 {
		return netip.Prefix{}, ErrPoolFull
	}
	next := netip.PrefixFrom(cur.Addr(), cur.Bits()-1).Masked()
	// The block keeps its network address only if it is the LOWER half of the next
	// coarser prefix; otherwise growing in place is not possible.
	if next.Addr() != cur.Addr() {
		return netip.Prefix{}, ErrPoolFull
	}
	// The grown block must still fit wholly inside the pool.
	if next.Bits() < r.pool.Bits() || !prefixInside(next, r.pool) {
		return netip.Prefix{}, ErrPoolFull
	}
	// The buddy is the half of next that is NOT cur — it must be wholly free.
	buddy := buddyOf(cur)
	free, err := r.rangeFree(ctx, buddy, name)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !free {
		return netip.Prefix{}, ErrPoolFull
	}
	res := r.db.WithContext(ctx).Model(&Netblock{}).
		Where("name = ? AND cidr = ?", name, cur.String()).
		Updates(map[string]any{"cidr": next.String()})
	if res.Error != nil {
		return netip.Prefix{}, fmt.Errorf("netblock: grow: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return netip.Prefix{}, ErrPoolFull // another grower won the race; caller re-reads
	}
	r.invalidate()
	r.recordAudit(ctx, actor, "netblock-autogrow", name, fmt.Sprintf(`{"cidr":%q}`, next.String()))
	return next, nil
}

// Resolve returns the CIDR for name; "" resolves to the 'default' netblock. An
// unknown/deleted non-empty name ALSO falls back to 'default' (with a warning), so a
// join-key/cloud-trust binding to a since-deleted or mistyped netblock never breaks
// enrollment (the documented AWSAccount.Netblock contract + ADR intent; D20). Only a
// missing 'default' (shouldn't happen post-genesis) yields ErrNotFound. It implements
// ipam.NetblockResolver. Backed by a small cache invalidated on CRUD.
func (r *Registry) Resolve(ctx context.Context, name string) (netip.Prefix, error) {
	c, err := r.snapshot(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	if name == "" {
		name = NameDefault
	}
	if p, ok := c.byName[name]; ok {
		return p, nil
	}
	// Unknown/deleted name -> fall back to 'default'.
	if name != NameDefault {
		r.logFallback(name)
		if p, ok := c.byName[NameDefault]; ok {
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("%w: %q", ErrNotFound, name)
}

// Carves returns the 'named' netblock CIDRs (for the allocator's overlap checks
// when filling 'default'). It implements ipam.NetblockResolver.
func (r *Registry) Carves(ctx context.Context) ([]netip.Prefix, error) {
	c, err := r.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := append([]netip.Prefix(nil), c.named...)
	return out, nil
}

// ResolveFull returns the netblock's id, CIDR, and named-ness for name ("" ->
// default), implementing ipam.IDResolver so the allocator can record netblock_id
// provenance and decide auto-grow eligibility.
func (r *Registry) ResolveFull(ctx context.Context, name string) (ipam.Resolved, error) {
	c, err := r.snapshot(ctx)
	if err != nil {
		return ipam.Resolved{}, err
	}
	if name == "" {
		name = NameDefault
	}
	row, ok := c.rows[name]
	if !ok {
		// Unknown/deleted name -> fall back to 'default' (D20). The resolved block is
		// 'default' (kind=default), so Named=false: an unknown binding must NOT become
		// auto-grow-eligible as if it were a named block — it draws from the bounded
		// fallback, which never auto-grows.
		if name != NameDefault {
			r.logFallback(name)
			if def, ok := c.rows[NameDefault]; ok {
				row = def
			} else {
				return ipam.Resolved{}, fmt.Errorf("%w: %q", ErrNotFound, name)
			}
		} else {
			return ipam.Resolved{}, fmt.Errorf("%w: %q", ErrNotFound, name)
		}
	}
	return ipam.Resolved{
		ID:    row.ID,
		Name:  row.Name,
		CIDR:  row.Prefix(),
		Named: row.Kind == KindNamed,
	}, nil
}

// logFallback emits a warning that an unknown/deleted netblock name fell back to the
// 'default' block at resolution time (D20), so the silent-but-safe fallback stays
// visible to operators.
func (r *Registry) logFallback(name string) {
	log := r.log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("netblock: unknown binding name fell back to default",
		"requested", name, "fallback", NameDefault)
}

// --- internals ---

// resolverCache is the cached, parsed snapshot of the netblocks table.
type resolverCache struct {
	byName map[string]netip.Prefix
	rows   map[string]Netblock // full row by name (for ResolveFull provenance)
	all    []netip.Prefix      // every netblock CIDR (for overlap checks)
	named  []netip.Prefix      // only kind=named (for the allocator's default-fill skip)
}

func (r *Registry) invalidate() {
	r.mu.Lock()
	r.cache = nil
	r.gen++ // a snapshot in flight against the old gen must not store its stale result
	r.mu.Unlock()
}

// snapshot returns the parsed netblock table, building (and caching) it on a miss.
// The build runs OUTSIDE the lock (List touches the DB; holding r.mu across it would
// serialize every reader and risk a deadlock with the single SQLite writer). A
// generation counter guards the lost-update race: invalidate() bumps r.gen, so a
// snapshot that began before a concurrent mutation refuses to store its now-stale
// result — it returns the freshly-built snapshot to its own caller but leaves the
// cache nil so the NEXT reader rebuilds against the mutated table.
func (r *Registry) snapshot(ctx context.Context) (*resolverCache, error) {
	r.mu.Lock()
	if r.cache != nil {
		c := r.cache
		r.mu.Unlock()
		return c, nil
	}
	startGen := r.gen
	r.mu.Unlock()

	rows, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	c := &resolverCache{
		byName: make(map[string]netip.Prefix, len(rows)),
		rows:   make(map[string]Netblock, len(rows)),
	}
	for _, row := range rows {
		p := row.Prefix()
		if !p.IsValid() {
			continue
		}
		c.byName[row.Name] = p
		c.rows[row.Name] = row
		c.all = append(c.all, p)
		if row.Kind == KindNamed {
			c.named = append(c.named, p)
		}
	}
	r.mu.Lock()
	if r.gen == startGen {
		r.cache = c // no mutation raced us — safe to publish
	}
	// else: a mutation invalidated mid-read; leave cache nil so the next reader
	// rebuilds. We still return c (a consistent point-in-time view) to this caller.
	r.mu.Unlock()
	return c, nil
}

// validateCIDR enforces: valid IPv4 prefix, inside the pool, and non-overlapping
// with every OTHER netblock (excludeName is skipped — itself, on edit) and with the
// pool's reservations.
func (r *Registry) validateCIDR(ctx context.Context, cidr netip.Prefix, excludeName string) error {
	if !cidr.IsValid() || !cidr.Addr().Is4() {
		return ErrBadCIDR
	}
	cidr = cidr.Masked()
	if !prefixInside(cidr, r.pool) {
		return fmt.Errorf("%w: %s not in %s", ErrOutOfPool, cidr, r.pool)
	}
	for _, res := range r.reserved {
		if cidr.Contains(res) {
			return fmt.Errorf("%w: reserved %s", ErrOverlap, res)
		}
	}
	rows, err := r.List(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Name == excludeName {
			continue
		}
		other := row.Prefix()
		if other.IsValid() && cidr.Overlaps(other) {
			return fmt.Errorf("%w: %s overlaps %s (%s)", ErrOverlap, cidr, row.Name, other)
		}
	}
	return nil
}

// checkNoStranded enforces the edit/remove stranding guard: every live allocation
// inside oldRange must still be inside newRange. A zero newRange (removal) strands
// any live allocation in oldRange.
func (r *Registry) checkNoStranded(ctx context.Context, oldRange, newRange netip.Prefix) error {
	if r.allocs == nil {
		return nil // no allocation source wired (CLI/tests) — nothing to strand
	}
	addrs, err := r.allocs.LiveAddrs(ctx)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if oldRange.IsValid() && oldRange.Contains(a) {
			if !newRange.IsValid() || !newRange.Contains(a) {
				return fmt.Errorf("%w: %s", ErrStranded, a)
			}
		}
	}
	return nil
}

// rangeFree reports whether rng overlaps no other netblock (excludeName skipped),
// no reservation, and no live allocation.
func (r *Registry) rangeFree(ctx context.Context, rng netip.Prefix, excludeName string) (bool, error) {
	for _, res := range r.reserved {
		if rng.Contains(res) {
			return false, nil
		}
	}
	rows, err := r.List(ctx)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.Name == excludeName {
			continue
		}
		if other := row.Prefix(); other.IsValid() && rng.Overlaps(other) {
			return false, nil
		}
	}
	if r.allocs != nil {
		addrs, err := r.allocs.LiveAddrs(ctx)
		if err != nil {
			return false, err
		}
		for _, a := range addrs {
			if rng.Contains(a) {
				return false, nil
			}
		}
	}
	return true, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}

// Suggest computes a growth-aware placement for a new /reqPrefixLen netblock
// against the live carves + reservations (Growth-Envelope with Worst-Fit
// Fallback, ADR 0010). It is a pure deterministic function — exported so the
// create UI's suggest endpoint and the server-side submit-time default share one
// implementation. The returned prefix is exactly /reqPrefixLen; the caller still
// enforces non-overlap/central/default on persist.
func (r *Registry) Suggest(ctx context.Context, reqPrefixLen int) (netip.Prefix, error) {
	carves, err := r.allCarves(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	return Suggest(reqPrefixLen, r.pool, r.reserved, carves)
}

// allCarves returns every netblock CIDR (all kinds — central, default, named) so
// Suggest avoids them all.
func (r *Registry) allCarves(ctx context.Context) ([]netip.Prefix, error) {
	c, err := r.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return append([]netip.Prefix(nil), c.all...), nil
}

// Suggest is the pure placement function (no DB) — see (*Registry).Suggest. It is
// the authoritative algorithm, called both server-side and (via the suggest
// endpoint) by the UI; identical inputs yield an identical result so the overlay
// redraws without jitter.
//
// Algorithm: round /P up to a CIDR-aligned growth envelope /E where
// E = clamp(P - MarginBits, lower = max(EnvelopeFloor, poolBits), upper = P), scan
// envelope-aligned slots lowest-first, and place the block at the START of the
// first envelope wholly free of reservations and carves (start placement lets the
// block grow in place P->P-1->... without relocating). Under pressure (no fresh
// envelope), pack into the partial envelope with the MOST free /P slots (worst-fit
// — keeps headroom maximal), then relax the margin, then plain first-free; return
// ErrPoolFull only when no aligned /P slot exists anywhere.
func Suggest(reqPrefixLen int, pool netip.Prefix, reserved []netip.Addr, carves []netip.Prefix) (netip.Prefix, error) {
	pool = pool.Masked()
	if !pool.IsValid() || !pool.Addr().Is4() {
		return netip.Prefix{}, ErrBadCIDR
	}
	P := reqPrefixLen
	if P < pool.Bits() || P > 32 {
		return netip.Prefix{}, ErrBadPrefixLen
	}

	// Growth envelope /E.
	floor := EnvelopeFloor
	if pool.Bits() > floor {
		floor = pool.Bits()
	}
	E := P - MarginBits
	if E < floor {
		E = floor
	}
	if E > P {
		E = P
	}

	// 1. First envelope wholly free of reservations + carves: place at its start.
	for _, env := range slots(pool, E) {
		if rangeClear(env, reserved, carves) {
			return netip.PrefixFrom(env.Addr(), P).Masked(), nil
		}
	}

	// 2. Worst-fit: the partial envelope with the most free aligned /P slots; place
	// at its lowest free /P. Deterministic tie-break: lowest-address envelope wins.
	bestFreeSlot := netip.Prefix{}
	bestCount := -1
	for _, env := range slots(pool, E) {
		free, count := freeSlotsIn(env, P, reserved, carves)
		if count > bestCount {
			bestCount = count
			bestFreeSlot = free
		}
	}
	if bestCount > 0 && bestFreeSlot.IsValid() {
		return bestFreeSlot, nil
	}

	// 3. Relax the margin (smaller envelope) down to /P, retrying step 1.
	for e := E + 1; e <= P; e++ {
		for _, env := range slots(pool, e) {
			if rangeClear(env, reserved, carves) {
				return netip.PrefixFrom(env.Addr(), P).Masked(), nil
			}
		}
	}

	// 4. Plain first-free over the whole pool at /P.
	for _, slot := range slots(pool, P) {
		if rangeClear(slot, reserved, carves) {
			return slot, nil
		}
	}

	return netip.Prefix{}, ErrPoolFull
}

// slots returns every /bits aligned prefix inside pool, lowest-address-first.
func slots(pool netip.Prefix, bits int) []netip.Prefix {
	if bits < pool.Bits() || bits > 32 {
		return nil
	}
	count := uint64(1) << uint(bits-pool.Bits())
	out := make([]netip.Prefix, 0, count)
	cur := netip.PrefixFrom(pool.Addr(), bits).Masked()
	for i := uint64(0); i < count; i++ {
		out = append(out, cur)
		next := nextSlot(cur)
		if !next.IsValid() {
			break
		}
		cur = next
	}
	return out
}

// nextSlot returns the next aligned prefix after p (same bits), or the zero value
// when the address space wraps.
func nextSlot(p netip.Prefix) netip.Prefix {
	addr := p.Masked().Addr()
	step := uint32(1) << (32 - p.Bits())
	v := addrToUint32(addr) + step
	if v < addrToUint32(addr) { // overflow/wrap
		return netip.Prefix{}
	}
	return netip.PrefixFrom(uint32ToAddr(v), p.Bits())
}

// freeSlotsIn returns the lowest free aligned /P slot inside env and the count of
// free /P slots in env (free = clear of reservations + carves).
func freeSlotsIn(env netip.Prefix, P int, reserved []netip.Addr, carves []netip.Prefix) (netip.Prefix, int) {
	var lowest netip.Prefix
	count := 0
	for _, slot := range slots(env, P) {
		if rangeClear(slot, reserved, carves) {
			count++
			if !lowest.IsValid() {
				lowest = slot
			}
		}
	}
	return lowest, count
}

// rangeClear reports whether rng overlaps no carve and contains no reservation.
func rangeClear(rng netip.Prefix, reserved []netip.Addr, carves []netip.Prefix) bool {
	for _, res := range reserved {
		if rng.Contains(res) {
			return false
		}
	}
	for _, c := range carves {
		if c.IsValid() && rng.Overlaps(c) {
			return false
		}
	}
	return true
}

// buddyOf returns the immediate doubling buddy of p — the sibling /P that, with p,
// completes the /P-1 it belongs to. For a start-of-envelope (lower-half) block this
// is the upper half the block grows into.
func buddyOf(p netip.Prefix) netip.Prefix {
	p = p.Masked()
	if p.Bits() <= 0 {
		return netip.Prefix{}
	}
	parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
	if parent.Addr() == p.Addr() {
		// p is the lower half — buddy is the upper half.
		step := uint32(1) << (32 - p.Bits())
		return netip.PrefixFrom(uint32ToAddr(addrToUint32(p.Addr())+step), p.Bits())
	}
	// p is the upper half — buddy is the lower half.
	step := uint32(1) << (32 - p.Bits())
	return netip.PrefixFrom(uint32ToAddr(addrToUint32(p.Addr())-step), p.Bits())
}

// prefixInside reports whether inner is wholly contained in outer.
func prefixInside(inner, outer netip.Prefix) bool {
	return inner.Bits() >= outer.Bits() && outer.Contains(inner.Masked().Addr())
}

func addrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
