package ca

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
)

// Collector is a scrape-time Prometheus source for the M8.4 CA key-deletion state — the signal a
// CloudWatch/Prometheus alarm watches so an operator is paged while a signing key sits in its
// pending-deletion window (the last chance to cancel before it is destroyed). Registered on Core's
// /metrics like the lighthouse/IPAM collectors.
type Collector struct {
	db  *gorm.DB
	now func() time.Time
}

// NewCollector builds a CA metrics collector over the store's DB.
func NewCollector(db *gorm.DB) *Collector { return &Collector{db: db, now: time.Now} }

var (
	descKeyDeletionPending = prometheus.NewDesc(
		"ncp_ca_key_deletion_pending",
		"Number of CA signing keys currently scheduled for deletion (M8.4; each is in its cancellable pending window).",
		nil, nil,
	)
	descKeyDeletionSeconds = prometheus.NewDesc(
		"ncp_ca_key_deletion_seconds_remaining",
		"Seconds until a CA signing key is destroyed (M8.4); labelled by CA. Negative once the window has elapsed. Alarm on a low/expiring value to catch an unintended deletion in time to cancel.",
		[]string{"id", "name", "fingerprint"}, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descKeyDeletionPending
	ch <- descKeyDeletionSeconds
}

// Collect emits the pending-deletion count and, per pending CA, the seconds until its key is
// destroyed. A DB error yields no samples this scrape (the gauge simply goes absent) rather than a
// panic — mirroring the lighthouse collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	reg := New(c.db, nil)
	rows, err := reg.PendingKeyDeletions(context.Background())
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(descKeyDeletionPending, prometheus.GaugeValue, float64(len(rows)))
	now := c.now().UTC().UnixNano()
	for _, r := range rows {
		remaining := time.Duration(r.KeyDeletionDate - now).Seconds()
		ch <- prometheus.MustNewConstMetric(descKeyDeletionSeconds, prometheus.GaugeValue, remaining,
			strconv.FormatInt(r.ID, 10), r.Name, r.Fingerprint)
	}
}

// RegisterCollector registers c on the default registry (idempotent — a duplicate registration is a
// no-op, so several boot paths can call it).
func RegisterCollector(c *Collector) error { return registerOn(prometheus.DefaultRegisterer, c) }

var (
	regMu   sync.Mutex
	regDone bool
)

func registerOn(reg prometheus.Registerer, c *Collector) error {
	if reg == nil || c == nil {
		return nil
	}
	regMu.Lock()
	defer regMu.Unlock()
	if regDone {
		return nil
	}
	if err := reg.Register(c); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
			regDone = true
			return nil
		}
		return err
	}
	regDone = true
	return nil
}
