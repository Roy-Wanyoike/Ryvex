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
