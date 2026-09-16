package state

import (
	"fmt"
	"testing"
)

// Internal retention tests (issue #85): these inspect the unexported
// ring state (write index, eviction counter, seq) that the public API
// deliberately does not expose. The behavior-level retention cases
// live in the shared statetest suite (RunAuditRetentionSuite, called
// from store_test.go) so they stay memory-only by construction.

// TestAuditRingDefaultCap: the zero-option store pre-allocates the
// default ring and starts with nothing evicted.
func TestAuditRingDefaultCap(t *testing.T) {
	s := NewStore()
	if s.auditCap != DefaultAuditCap {
		t.Fatalf("default audit cap = %d, want %d", s.auditCap, DefaultAuditCap)
	}
	if cap(s.audit) != DefaultAuditCap || len(s.audit) != 0 {
		t.Fatalf("ring not pre-allocated to the cap: len=%d cap=%d", len(s.audit), cap(s.audit))
	}
	if s.AuditEvicted() != 0 {
		t.Fatalf("fresh store must not report evictions, got %d", s.AuditEvicted())
	}
}

// TestAuditRingCapFallback: non-positive caps fall back to the
// default instead of producing an unbounded or zero-cap log.
func TestAuditRingCapFallback(t *testing.T) {
	for _, n := range []int{0, -1, -10000} {
		s := NewStore(WithAuditCap(n))
		if s.auditCap != DefaultAuditCap {
			t.Fatalf("WithAuditCap(%d): cap = %d, want default %d", n, s.auditCap, DefaultAuditCap)
		}
		if cap(s.audit) != DefaultAuditCap {
			t.Fatalf("WithAuditCap(%d): ring capacity = %d, want default %d", n, cap(s.audit), DefaultAuditCap)
		}
	}
}

// TestAuditRingWrapsAndSeqStaysMonotonic: at the cap the ring
// overwrites oldest-first; seq keeps counting every append and is
// never reset or forked by eviction (mirroring the pgstore seq column
// that orders its audit listing); the newest-first walk reads the
// ring correctly across the wrap point.
func TestAuditRingWrapsAndSeqStaysMonotonic(t *testing.T) {
	const size = 4
	s := NewStore(WithAuditCap(size))
	for i := 0; i < 2*size+1; i++ {
		if _, err := s.AppendAudit(AuditEntry{
			Actor:      fmt.Sprintf("a%d", i),
			Action:     "webhook_delivered",
			Kind:       "Subscription",
			LogicalKey: "acme/core/prod/Subscription/hook",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if s.seq != 2*size+1 {
		t.Fatalf("seq = %d, want %d (eviction must not reset the sequence)", s.seq, 2*size+1)
	}
	if s.auditEvicted != size+1 {
		t.Fatalf("evicted = %d, want %d", s.auditEvicted, size+1)
	}
	if got := s.AuditEvicted(); got != uint64(size+1) {
		t.Fatalf("AuditEvicted = %d, want %d", got, size+1)
	}
	if len(s.audit) != size || s.auditWrite != (2*size+1)%size {
		t.Fatalf("ring state: len=%d write=%d, want len=%d write=%d", len(s.audit), s.auditWrite, size, (2*size+1)%size)
	}
	// newest-first across the wrap: writes 5..8 survive, 0..4 evicted
	entries, err := s.ListAudit(AuditOptions{Limit: 500})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	want := []string{"a8", "a7", "a6", "a5"}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for k, e := range entries {
		if e.Actor != want[k] {
			t.Fatalf("entry %d = %s, want %s (newest-first across the wrap)", k, e.Actor, want[k])
		}
	}
}
