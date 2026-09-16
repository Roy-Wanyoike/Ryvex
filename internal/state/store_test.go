package state_test

import (
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
	"github.com/Roy-Wanyoike/Ryvex/internal/state/statetest"
)

// The in-memory reference store must pass the exact same behavioral
// suite as every durable backend (see internal/state/pgstore). The
// original hand-written cases all live in the shared suite now.
func TestStoreSuite(t *testing.T) {
	statetest.RunSuite(t, func(t *testing.T) statetest.Store {
		return state.NewStore()
	})
}

// The bounded-audit-retention cases (issue #85) run for the memory
// backend only — the ring is a memory construct; pgstore asserts no
// cap instead (its audit table is the durable compliance record, see
// the suite's parity note). The cap is deliberately small so the
// eviction boundary is crossed in microseconds, not megabytes.
func TestStoreAuditRetention(t *testing.T) {
	statetest.RunAuditRetentionSuite(t, 8, func(t *testing.T) statetest.Store {
		return state.NewStore(state.WithAuditCap(8))
	})
}

// TestStoreUpdateNoOpKeepsUpdatedAt pins the in-memory store's #108
// semantics: a no-op update leaves UpdatedAt untouched (the
// byte-identical heartbeat invariant) while a real change stamps a
// fresh UpdatedAt alongside the generation bump. The durable backend
// has had the same guarantee since pgstore parity landed (issue #115,
// PR #116): pgstore.UpdateResource detects no-ops via JSON equality on
// the locked pre-image and stores a byte-identical row, and the shared
// statetest suite runs UpdateNoOpPreservesUpdatedAt against every
// backend. This hand-written case stays as a direct pin on the
// reference in-memory store.
func TestStoreUpdateNoOpKeepsUpdatedAt(t *testing.T) {
	s := state.NewStore()
	created, err := s.CreateResource(&state.Resource{
		Kind: "Application", Org: "acme", Project: "core", Env: "prod", Name: "checkout",
		Labels: map[string]string{"managed-by": "ryvex"},
		Spec:   map[string]any{"image": "checkout:1"},
	}, state.WriteOptions{Actor: "t"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// No-op: the resource comes back unchanged - same generation, same
	// UpdatedAt.
	same, err := s.UpdateResource(created.ID, func(cur *state.Resource) error { return nil },
		state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	if !same.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("no-op update stamped UpdatedAt: %v -> %v", created.UpdatedAt, same.UpdatedAt)
	}
	if same.Generation != created.Generation {
		t.Fatalf("no-op update bumped generation: %d -> %d", created.Generation, same.Generation)
	}

	// Real change: UpdatedAt advances with the generation bump.
	changed, err := s.UpdateResource(created.ID, func(cur *state.Resource) error {
		cur.Spec["image"] = "checkout:2"
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("change update: %v", err)
	}
	if changed.Generation != created.Generation+1 {
		t.Fatalf("change: generation = %d, want %d", changed.Generation, created.Generation+1)
	}
	if !changed.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("change: UpdatedAt = %v, want after %v", changed.UpdatedAt, created.UpdatedAt)
	}
}
