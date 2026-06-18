// Package ipam allocates overlay IP addresses for Harbor (implementation-plan
// M2.6). Allocations are collision-free under concurrency — the UNIQUE(ip)
// constraint in the database is the source of truth, and racing allocators that
// pick the same address simply retry. Released addresses enter a quarantine
// window before they can be reused, so a recycled IP can't be confused with a
// host that may still hold a (soon-to-expire) certificate for it.
//
// IPAM (ADR 0010) layers NAMED NETBLOCKS on top: each allocation resolves a
// netblock NAME (empty -> the bounded 'default' block) to a CIDR via a
// NetblockResolver and fills sequentially within it, so related hosts cluster by
// join source. Every allocation records its netblock + join method (provenance).
// A full 'named' block auto-grows into its free immediate buddy and retries;
// 'central'/'default' are deliberately sized and do not auto-grow.
package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/gorm"
)

const (
	stateAllocated   = "allocated"
	stateQuarantined = "quarantined"
	maxAllocAttempts = 100

	// NameDefault is the netblock name an empty request resolves to (the bounded
	// fallback). Kept here too (not only in internal/netblock) so ipam stays free of
	// an import cycle on the resolver's concrete type.
	NameDefault = "default"
)

// Errors.
var (
	ErrPoolExhausted   = errors.New("ipam: no free addresses in range")
	ErrUnknownSubRange = errors.New("ipam: unknown sub-range")
	ErrNotAllocated    = errors.New("ipam: address is not allocated")
	ErrContended       = errors.New("ipam: allocation contended, retries exhausted")
	ErrAddrTaken       = errors.New("ipam: address already allocated")
	ErrOutOfPool       = errors.New("ipam: address not in pool")
)

// IPAM Prometheus EVENT counters (ADR 0010 — "Auto-grow, exhaustion & surfacing").
// Registered on the default registry at init, scraped like the rest of ncp_*; these
// are imperative because they mark moments in time (a grow happened, an enrollment was
// denied), so a counter Inc at the event is exactly right. The per-netblock UTILIZATION
// gauges (capacity/allocated/used) are NOT here — they decay between alloc events (a
// host going stale drops `used` with no allocation to hang an Inc on), so they are
// emitted by a scrape-time NetblockCollector (D23) reading live state at /metrics.
// Labelled by netblock (low cardinality — the few admin-carved blocks + central/default).
var (
	metricAutogrow = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_ipam_autogrow_total",
		Help: "Auto-grow events (a full named netblock doubled into its free buddy), by netblock.",
	}, []string{"netblock"})
	metricExhausted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_ipam_exhausted_total",
		Help: "Exhaustion denials (no address available, buddy occupied or non-growing block) that denied an enrollment, by netblock.",
	}, []string{"netblock"})
)

// Device is an enrolled host identity (minimal until the 2.12 lifecycle work).
type Device struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	Name      string `gorm:"column:name"`
	CreatedAt int64  `gorm:"column:created_at"`
}

func (Device) TableName() string { return "devices" }

// Allocation is a single overlay-IP lease. NetblockID + Method are the ADR-0010
// provenance: which netblock the address came from and which join method drove it.
type Allocation struct {
	ID              int64  `gorm:"column:id;primaryKey"`
	IP              string `gorm:"column:ip"`
	DeviceID        int64  `gorm:"column:device_id"`
	State           string `gorm:"column:state"`
	AllocatedAt     int64  `gorm:"column:allocated_at"`
	ReleasedAt      int64  `gorm:"column:released_at"`
	QuarantineUntil int64  `gorm:"column:quarantine_until"`
	NetblockID      int64  `gorm:"column:netblock_id"` // 0 = none recorded
	Method          string `gorm:"column:method"`      // token | aws-sigv4 | sso | genesis
}

func (Allocation) TableName() string { return "ip_allocations" }

// NetblockResolver maps a netblock NAME to its CIDR at allocation time, keeping
// ipam storage-agnostic. *netblock.Registry implements it; the static SubRanges
// map (below) provides a no-DB impl for tests/CLI. Resolve("") -> the default
// block. Carves returns the named CIDRs so a 'default' fill can skip them.
type NetblockResolver interface {
	Resolve(ctx context.Context, name string) (netip.Prefix, error)
	Carves(ctx context.Context) ([]netip.Prefix, error)
}

// NetblockGrower lets the allocator auto-grow a full 'named' netblock into its free
// immediate buddy (the registry implements it transactionally). Optional: an
// allocator with no grower simply returns ErrPoolExhausted on a full block.
type NetblockGrower interface {
	// Grow extends the named netblock one doubling (/P -> /P-1, same network
	// address) if its buddy is free, returning the new prefix; ErrPoolFull-class
	// errors mean the buddy is occupied (no grow possible).
	Grow(ctx context.Context, name, actor string) (netip.Prefix, error)
}

// Resolved is the netblock a name resolved to: its id (for provenance), CIDR, and
// whether it is a 'named' (auto-growable) block.
type Resolved struct {
	ID    int64
	Name  string
	CIDR  netip.Prefix
	Named bool // true for kind=named (eligible for auto-grow)
}

// IDResolver, when implemented by the resolver, lets the allocator record the
// netblock_id provenance and decide auto-grow eligibility. *netblock.Registry
// implements it; the static map does not (provenance stays 0).
type IDResolver interface {
	ResolveFull(ctx context.Context, name string) (Resolved, error)
}

// Pool configures the overlay address space. SubRanges carve per-cloud/region
// blocks (a static, no-DB resolver for tests/CLI) and must each be inside Prefix.
type Pool struct {
	Prefix        netip.Prefix
	SubRanges     map[string]netip.Prefix
	Reserved      []netip.Addr  // never handed out (e.g. lighthouse IPs)
	QuarantineTTL time.Duration // 0 = reuse immediately on release
}

// Allocator hands out addresses from a Pool, backed by the store.
type Allocator struct {
	db       *gorm.DB
	pool     Pool
	resolver NetblockResolver // optional; nil -> SubRanges-only behavior
	grower   NetblockGrower   // optional; nil -> no auto-grow
	now      func() time.Time
}

// NewAllocator validates the pool and returns an Allocator with no netblock
// resolver (the legacy SubRanges behavior, for tests/CLI).
func NewAllocator(s *store.Store, pool Pool) (*Allocator, error) {
	if !pool.Prefix.IsValid() || !pool.Prefix.Addr().Is4() {
		return nil, fmt.Errorf("ipam: pool prefix must be a valid IPv4 prefix")
	}
	for name, sr := range pool.SubRanges {
		if !sr.IsValid() || !sr.Addr().Is4() {
			return nil, fmt.Errorf("ipam: sub-range %q is not a valid IPv4 prefix", name)
		}
		if !pool.Prefix.Contains(sr.Addr()) {
			return nil, fmt.Errorf("ipam: sub-range %q (%s) is not inside pool %s", name, sr, pool.Prefix)
		}
	}
	return &Allocator{db: s.DB, pool: pool, now: time.Now}, nil
}

// WithResolver returns a copy of the allocator that resolves netblock NAMES via r
// (and, if r also implements NetblockGrower, auto-grows full named blocks). This is
// the production wiring (DB-backed netblock.Registry); the legacy SubRanges path
// stays for tests/CLI.
func (a *Allocator) WithResolver(r NetblockResolver) *Allocator {
	cp := *a
	cp.resolver = r
	if g, ok := r.(NetblockGrower); ok {
		cp.grower = g
	}
	return &cp
}

// Allocate leases the lowest free address in the netblock named netblockName to
// deviceName, recording the join method. An empty name resolves to the bounded
// 'default' block (or, with no resolver, the whole pool). A full 'named' block
// auto-grows into its free buddy and retries; otherwise ErrPoolExhausted denies
// the enrollment (surfaced via the exhaustion metric + caller audit).
func (a *Allocator) Allocate(ctx context.Context, deviceName, netblockName, method string) (netip.Addr, error) {
	res, err := a.resolve(ctx, netblockName)
	if err != nil {
		return netip.Addr{}, err
	}

	dev, err := a.ensureDevice(ctx, deviceName)
	if err != nil {
		return netip.Addr{}, err
	}

	// Reclaim expired quarantine rows once, up front, so their IPs are free.
	if err := a.purgeExpiredQuarantine(ctx); err != nil {
		return netip.Addr{}, err
	}

	for attempt := 0; attempt < maxAllocAttempts; attempt++ {
		ip, ferr := a.firstFree(ctx, res)
		if errors.Is(ferr, ErrPoolExhausted) {
			// Auto-grow a full named block into its free buddy, then retry once per grow.
			if res.Named && a.grower != nil {
				grown, gerr := a.grower.Grow(ctx, res.Name, "ipam-autogrow")
				if gerr == nil && grown.IsValid() {
					metricAutogrow.WithLabelValues(res.Name).Inc()
					res.CIDR = grown
					continue
				}
			}
			metricExhausted.WithLabelValues(metricName(res)).Inc()
			return netip.Addr{}, ferr
		}
		if ferr != nil {
			return netip.Addr{}, ferr
		}
		alloc := Allocation{
			IP:          ip.String(),
			DeviceID:    dev.ID,
			State:       stateAllocated,
			AllocatedAt: a.now().UnixNano(),
			NetblockID:  res.ID,
			Method:      method,
		}
		err = a.db.WithContext(ctx).Create(&alloc).Error
		if err == nil {
			// Utilization gauges (capacity/allocated/used) are emitted at scrape time by
			// NetblockCollector (D23) — a successful allocation needs no metric refresh
			// here; the next /metrics scrape reflects it from live state.
			return ip, nil
		}
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			continue // another allocator took this IP; pick the next free one
		}
		return netip.Addr{}, fmt.Errorf("ipam: allocate: %w", err)
	}
	return netip.Addr{}, ErrContended
}

// AllocateSpecific leases a chosen address (e.g. a reserved lighthouse IP at
// genesis), recording method. Returns ErrAddrTaken if it is already in use,
// ErrOutOfPool if it is outside the pool.
func (a *Allocator) AllocateSpecific(ctx context.Context, deviceName string, addr netip.Addr, method string) error {
	if !a.pool.Prefix.Contains(addr) {
		return fmt.Errorf("%w: %s not in %s", ErrOutOfPool, addr, a.pool.Prefix)
	}
	dev, err := a.ensureDevice(ctx, deviceName)
	if err != nil {
		return err
	}
	if err := a.purgeExpiredQuarantine(ctx); err != nil {
		return err
	}
	// Record provenance against the netblock that contains addr, if a resolver is
	// wired (best-effort; a miss leaves netblock_id 0 — still a valid allocation).
	var netblockID int64
	if id, ok := a.netblockIDContaining(ctx, addr); ok {
		netblockID = id
	}
	alloc := Allocation{
		IP:          addr.String(),
		DeviceID:    dev.ID,
		State:       stateAllocated,
		AllocatedAt: a.now().UnixNano(),
		NetblockID:  netblockID,
		Method:      method,
	}
	err = a.db.WithContext(ctx).Create(&alloc).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return fmt.Errorf("%w: %s", ErrAddrTaken, addr)
	}
	if err != nil {
		return fmt.Errorf("ipam: allocate specific: %w", err)
	}
	return nil
}

// Release returns an address to the pool. With a QuarantineTTL it is held
// (unusable) until the window passes; without one it is freed immediately.
func (a *Allocator) Release(ctx context.Context, ip netip.Addr) error {
	now := a.now()
	if a.pool.QuarantineTTL <= 0 {
		res := a.db.WithContext(ctx).Where("ip = ?", ip.String()).Delete(&Allocation{})
		if res.Error != nil {
			return fmt.Errorf("ipam: release: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrNotAllocated
		}
		return nil
	}
	res := a.db.WithContext(ctx).Model(&Allocation{}).
		Where("ip = ? AND state = ?", ip.String(), stateAllocated).
		Updates(map[string]any{
			"state":            stateQuarantined,
			"released_at":      now.UnixNano(),
			"quarantine_until": now.Add(a.pool.QuarantineTTL).UnixNano(),
		})
	if res.Error != nil {
		return fmt.Errorf("ipam: release: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotAllocated
	}
	return nil
}

// LiveAddrs returns every live overlay address — allocated, OR quarantined with an
// unexpired window. It backs netblock.Registry's stranding guard (an edit/remove that
// would leave a live allocation outside the new range is blocked). An expired-but-
// unpurged quarantine row is NOT live (its IP is reusable), so it's excluded here to
// avoid falsely tripping ErrStranded on a netblock edit/remove.
func (a *Allocator) LiveAddrs(ctx context.Context) ([]netip.Addr, error) {
	var ips []string
	err := a.db.WithContext(ctx).Model(&Allocation{}).
		Where("state = ? OR quarantine_until > ?", stateAllocated, a.now().UnixNano()).
		Pluck("ip", &ips).Error
	if err != nil {
		return nil, fmt.Errorf("ipam: live addrs: %w", err)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr)
		}
	}
	return out, nil
}

func (a *Allocator) ensureDevice(ctx context.Context, name string) (Device, error) {
	var dev Device
	err := a.db.WithContext(ctx).
		Where(Device{Name: name}).
		Attrs(Device{CreatedAt: a.now().UnixNano()}).
		FirstOrCreate(&dev).Error
	if err != nil {
		return Device{}, fmt.Errorf("ipam: ensure device %q: %w", name, err)
	}
	return dev, nil
}

func (a *Allocator) purgeExpiredQuarantine(ctx context.Context) error {
	err := a.db.WithContext(ctx).
		Where("state = ? AND quarantine_until <= ?", stateQuarantined, a.now().UnixNano()).
		Delete(&Allocation{}).Error
	if err != nil {
		return fmt.Errorf("ipam: purge quarantine: %w", err)
	}
	return nil
}

// resolve maps netblockName to the CIDR + provenance to fill. Precedence: a wired
// netblock resolver (production); else the static SubRanges map (tests/CLI); else
// the whole pool. An empty name -> the 'default' netblock (resolver) or the whole
// pool (no resolver).
func (a *Allocator) resolve(ctx context.Context, netblockName string) (Resolved, error) {
	if a.resolver != nil {
		if idr, ok := a.resolver.(IDResolver); ok {
			return idr.ResolveFull(ctx, netblockName)
		}
		cidr, err := a.resolver.Resolve(ctx, netblockName)
		if err != nil {
			return Resolved{}, err
		}
		return Resolved{Name: nameOrDefault(netblockName), CIDR: cidr}, nil
	}
	// Legacy SubRanges path: empty name -> whole pool.
	if netblockName == "" {
		return Resolved{Name: "", CIDR: a.pool.Prefix}, nil
	}
	sr, ok := a.pool.SubRanges[netblockName]
	if !ok {
		return Resolved{}, fmt.Errorf("%w: %q", ErrUnknownSubRange, netblockName)
	}
	return Resolved{Name: netblockName, CIDR: sr}, nil
}

func nameOrDefault(name string) string {
	if name == "" {
		return NameDefault
	}
	return name
}

func metricName(res Resolved) string {
	if res.Name == "" {
		return NameDefault
	}
	return res.Name
}

// netblockIDContaining resolves the netblock id (if any) whose CIDR contains addr,
// for AllocateSpecific provenance. Best-effort: needs a resolver implementing
// IDResolver-by-name is awkward (we have an addr), so we scan the resolver's
// carves + named-or-not via ResolveFull on known control-plane names.
func (a *Allocator) netblockIDContaining(ctx context.Context, addr netip.Addr) (int64, bool) {
	idr, ok := a.resolver.(IDResolver)
	if !ok || a.resolver == nil {
		return 0, false
	}
	// Genesis allocations land in 'central'; try it first (the common case).
	for _, name := range []string{"central", NameDefault} {
		if r, err := idr.ResolveFull(ctx, name); err == nil && r.CIDR.Contains(addr) {
			return r.ID, true
		}
	}
	return 0, false
}

// firstFree returns the lowest address in res.CIDR that is neither reserved nor
// currently occupied (allocated or in-quarantine). When filling the 'default'
// block (a non-named block with a resolver), it additionally skips any address
// inside a 'named' carve, so default-fill never bleeds into a carved sub-range.
func (a *Allocator) firstFree(ctx context.Context, res Resolved) (netip.Addr, error) {
	rng := res.CIDR
	var ips []string
	if err := a.db.WithContext(ctx).Model(&Allocation{}).Pluck("ip", &ips).Error; err != nil {
		return netip.Addr{}, fmt.Errorf("ipam: load allocations: %w", err)
	}
	occupied := make(map[netip.Addr]bool, len(ips))
	for _, s := range ips {
		if addr, err := netip.ParseAddr(s); err == nil {
			occupied[addr] = true
		}
	}
	reserved := make(map[netip.Addr]bool, len(a.pool.Reserved))
	for _, r := range a.pool.Reserved {
		reserved[r] = true
	}

	// When filling 'default' (not a named block), skip addresses inside named carves
	// so a carve nested in the default range is never bled into.
	var carves []netip.Prefix
	if a.resolver != nil && !res.Named {
		if cs, err := a.resolver.Carves(ctx); err == nil {
			for _, c := range cs {
				if rng.Overlaps(c) {
					carves = append(carves, c)
				}
			}
		}
	}

	network := rng.Masked().Addr() // skip the network base address
	for addr := network; rng.Contains(addr); addr = addr.Next() {
		if addr == network || reserved[addr] || occupied[addr] {
			continue
		}
		if inAnyCarve(addr, carves) {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

func inAnyCarve(addr netip.Addr, carves []netip.Prefix) bool {
	for _, c := range carves {
		if c.Contains(addr) {
			return true
		}
	}
	return false
}

// hostCapacity is the usable host count of an IPv4 CIDR: 2^(32-bits) minus the
// network base address we never hand out. (A /31 or /32 yields a tiny/zero usable
// count, matching firstFree's network-skip.)
func hostCapacity(p netip.Prefix) int64 {
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return 0
	}
	total := int64(1) << uint(32-bits)
	if total <= 1 {
		return 0
	}
	return total - 1 // minus the network address
}
