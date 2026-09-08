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
