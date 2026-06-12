// Package ipam allocates overlay IP addresses for Harbor (implementation-plan
// M2.6). Allocations are collision-free under concurrency — the UNIQUE(ip)
// constraint in the database is the source of truth, and racing allocators that
// pick the same address simply retry. Released addresses enter a quarantine
// window before they can be reused, so a recycled IP can't be confused with a
// host that may still hold a (soon-to-expire) certificate for it.
package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"gorm.io/gorm"
)

const (
	stateAllocated   = "allocated"
	stateQuarantined = "quarantined"
	maxAllocAttempts = 100
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

// Device is an enrolled host identity (minimal until the 2.12 lifecycle work).
type Device struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	Name      string `gorm:"column:name"`
	CreatedAt int64  `gorm:"column:created_at"`
}

func (Device) TableName() string { return "devices" }

// Allocation is a single overlay-IP lease.
type Allocation struct {
	ID              int64  `gorm:"column:id;primaryKey"`
	IP              string `gorm:"column:ip"`
	DeviceID        int64  `gorm:"column:device_id"`
	State           string `gorm:"column:state"`
	AllocatedAt     int64  `gorm:"column:allocated_at"`
	ReleasedAt      int64  `gorm:"column:released_at"`
	QuarantineUntil int64  `gorm:"column:quarantine_until"`
}

func (Allocation) TableName() string { return "ip_allocations" }

// Pool configures the overlay address space. SubRanges carve per-cloud/region
// blocks (design §6.3) and must each be inside Prefix.
type Pool struct {
	Prefix        netip.Prefix
	SubRanges     map[string]netip.Prefix
	Reserved      []netip.Addr  // never handed out (e.g. lighthouse IPs)
	QuarantineTTL time.Duration // 0 = reuse immediately on release
}

// Allocator hands out addresses from a Pool, backed by the store.
type Allocator struct {
	db   *gorm.DB
	pool Pool
	now  func() time.Time
}

// NewAllocator validates the pool and returns an Allocator.
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

// Allocate leases the lowest free address in the pool (or in subRange, if given)
// to deviceName, creating the device record if needed.
func (a *Allocator) Allocate(ctx context.Context, deviceName, subRange string) (netip.Addr, error) {
	rng := a.pool.Prefix
	if subRange != "" {
		sr, ok := a.pool.SubRanges[subRange]
		if !ok {
			return netip.Addr{}, fmt.Errorf("%w: %q", ErrUnknownSubRange, subRange)
		}
		rng = sr
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
		ip, err := a.firstFree(ctx, rng)
		if err != nil {
			return netip.Addr{}, err
		}
		alloc := Allocation{
			IP:          ip.String(),
			DeviceID:    dev.ID,
			State:       stateAllocated,
			AllocatedAt: a.now().UnixNano(),
		}
		err = a.db.WithContext(ctx).Create(&alloc).Error
		if err == nil {
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
// genesis). Returns ErrAddrTaken if it is already in use, ErrOutOfPool if it is
// outside the pool.
func (a *Allocator) AllocateSpecific(ctx context.Context, deviceName string, addr netip.Addr) error {
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
	alloc := Allocation{
		IP:          addr.String(),
		DeviceID:    dev.ID,
		State:       stateAllocated,
		AllocatedAt: a.now().UnixNano(),
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

// firstFree returns the lowest address in rng that is neither reserved nor
// currently occupied (allocated or in-quarantine).
func (a *Allocator) firstFree(ctx context.Context, rng netip.Prefix) (netip.Addr, error) {
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

	network := rng.Masked().Addr() // skip the network base address
	for addr := network; rng.Contains(addr); addr = addr.Next() {
		if addr == network || reserved[addr] || occupied[addr] {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}
