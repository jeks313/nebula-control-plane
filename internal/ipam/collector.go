package ipam

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
)

// IPAM per-netblock UTILIZATION gauges (ADR 0010, D23). Unlike the autogrow/exhausted
// EVENT counters in ipam.go (which Inc at a moment), these decay between allocation
// events: `used` drops as hosts go stale with no allocation to hang an Inc on, and
// `allocated` drops on a quarantine purge. So they are computed at SCRAPE TIME by
// NetblockCollector — a prometheus.Collector that reads live store + registry state on
// each /metrics request — rather than set imperatively. Labelled by netblock (low
// cardinality — the few admin-carved blocks + central/default).
var (
	descNetblockCapacity = prometheus.NewDesc(
		"ncp_ipam_netblock_capacity",
		"Usable address capacity of a netblock (its CIDR's host count), by netblock.",
		[]string{"netblock"}, nil,
	)
	descNetblockAllocated = prometheus.NewDesc(
		"ncp_ipam_netblock_allocated",
		"Live (allocated or unexpired-quarantine; excludes expired-but-unpurged quarantine) addresses in a netblock, by netblock.",
		[]string{"netblock"}, nil,
	)
	descNetblockUsed = prometheus.NewDesc(
		"ncp_ipam_netblock_used",
		"Live (heartbeat-confirmed within the fleet stale window) addresses in a netblock, by netblock.",
		[]string{"netblock"}, nil,
	)
)

// NamedCIDR is one netblock's name + parsed CIDR — the minimal view the collector
// needs from the registry, defined here (not as netblock.Netblock) so ipam stays free
// of an import cycle on the netblock package (which already imports ipam).
type NamedCIDR struct {
	Name string
	CIDR netip.Prefix
}

// NetblockLister yields the current netblock name/CIDR set. *netblock.Registry
// implements it (NetblockCIDRs); the collector depends only on this minimal interface
// to avoid the ipam<-netblock import cycle.
type NetblockLister interface {
	NetblockCIDRs(ctx context.Context) ([]NamedCIDR, error)
}

// NetblockCollector emits the per-netblock utilization gauges at scrape time. It reads
// the registry (the netblock set) and the store (allocations + fresh heartbeats) on
// each Collect, so the values are always live — no allocation event is needed to keep
// `used` honest as hosts go stale. `used` counts allocations whose overlay IP has a
// heartbeat within staleAfter (the SAME freshness window the fleet uses, so "used" and
// the fleet's "stale" verdict agree, D23); `allocated` counts allocations whose IP
// falls in the netblock CIDR; `capacity` is the CIDR host count (minus the network
// address, matching the allocator). It is robust to a nil registry/store (emits
// nothing) and never panics on a transient query error (skips that scrape's emission).
type NetblockCollector struct {
	db         *gorm.DB
	blocks     NetblockLister
	staleAfter time.Duration
	now        func() time.Time
}

// NewNetblockCollector builds the collector over a store DB, the netblock lister, and
// the fleet stale window. A zero staleAfter defaults to 5m (the fleet default), so
// "used" matches the fleet's "stale" verdict.
func NewNetblockCollector(db *gorm.DB, blocks NetblockLister, staleAfter time.Duration) *NetblockCollector {
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	return &NetblockCollector{db: db, blocks: blocks, staleAfter: staleAfter, now: time.Now}
}

// Describe implements prometheus.Collector. The collector is "unchecked" w.r.t. the
// dynamic netblock label set, so we still send the descs (gives the registry the metric
// names/help) — but emitting no descs would also be valid for a fully dynamic collector.
func (c *NetblockCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descNetblockCapacity
	ch <- descNetblockAllocated
	ch <- descNetblockUsed
}

// Collect implements prometheus.Collector. Computes capacity/allocated/used per netblock
// from live state. Nil registry/store -> emit nothing; a transient query error -> skip
// (don't panic, don't emit a partial/wrong series for this scrape).
func (c *NetblockCollector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.db == nil || c.blocks == nil {
		return
	}
	ctx := context.Background()

	named, err := c.blocks.NetblockCIDRs(ctx)
	if err != nil {
		return
	}
	allocIPs, err := c.allocationAddrs(ctx)
	if err != nil {
		return
	}
	fresh, err := c.freshAddrs(ctx)
	if err != nil {
		return
	}

	for _, nb := range named {
		p := nb.CIDR
		if !p.IsValid() {
			continue
		}
		capacity := hostCapacity(p)
		allocated := 0
		used := 0
		for _, a := range allocIPs {
			if !p.Contains(a) {
				continue
			}
			allocated++
			if fresh[a] {
				used++
			}
		}
		ch <- prometheus.MustNewConstMetric(descNetblockCapacity, prometheus.GaugeValue, float64(capacity), nb.Name)
		ch <- prometheus.MustNewConstMetric(descNetblockAllocated, prometheus.GaugeValue, float64(allocated), nb.Name)
		ch <- prometheus.MustNewConstMetric(descNetblockUsed, prometheus.GaugeValue, float64(used), nb.Name)
	}
}

// allocationAddrs plucks every LIVE allocation IP — allocated, OR quarantined with an
// unexpired window — as parsed addrs. This matches ipam.LiveAddrs' predicate, so an
// expired-but-unpurged quarantine row (its IP is reusable, purged lazily on the next
// allocation) is excluded and not briefly counted as allocated.
func (c *NetblockCollector) allocationAddrs(ctx context.Context) ([]netip.Addr, error) {
	var ips []string
	if err := c.db.WithContext(ctx).Model(&Allocation{}).
		Where("state = ? OR quarantine_until > ?", stateAllocated, c.now().UnixNano()).
		Pluck("ip", &ips).Error; err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// heartbeat is the minimal read-model of the heartbeats table the collector needs.
type heartbeat struct {
	OverlayIP string `gorm:"column:overlay_ip"`
	LastSeen  int64  `gorm:"column:last_seen"`
}

func (heartbeat) TableName() string { return "heartbeats" }

// freshAddrs returns the set of overlay IPs whose heartbeat is within the stale window
// (last_seen >= now - staleAfter) — i.e. the fleet's "not stale" set. These are the
// addresses that count as "used".
func (c *NetblockCollector) freshAddrs(ctx context.Context) (map[netip.Addr]bool, error) {
	cutoff := c.now().UnixNano() - c.staleAfter.Nanoseconds()
	var ips []string
	if err := c.db.WithContext(ctx).Model(&heartbeat{}).
		Where("last_seen >= ?", cutoff).
		Pluck("overlay_ip", &ips).Error; err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]bool, len(ips))
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out[a] = true
		}
	}
	return out, nil
}

// RegisterNetblockCollector registers c on the default Prometheus registry, but at most
// ONCE per process: long-running servers wire it where store+registry+thresholds are
// available (core-api, admin-api), and a process that ends up calling this more than
// once (or in which an old imperative GaugeVec already owns the name) must not panic.
// A prometheus.AlreadyRegisteredError (duplicate name/collector) is swallowed as a
// no-op; any other registration error is returned to the caller. Guarded by a
// once-style flag so the common double-call is a cheap no-op.
func RegisterNetblockCollector(c *NetblockCollector) error {
	return registerNetblockCollectorOn(prometheus.DefaultRegisterer, c)
}

var (
	collectorRegMu   sync.Mutex
	collectorRegDone bool
)

func registerNetblockCollectorOn(reg prometheus.Registerer, c *NetblockCollector) error {
	if reg == nil || c == nil {
		return nil
	}
	collectorRegMu.Lock()
	defer collectorRegMu.Unlock()
	if collectorRegDone {
		return nil // already registered in this process — no-op (no double-register panic)
	}
	if err := reg.Register(c); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
			collectorRegDone = true
			return nil // a collector with this name is already present — treat as success
		}
		return err
	}
	collectorRegDone = true
	return nil
}
