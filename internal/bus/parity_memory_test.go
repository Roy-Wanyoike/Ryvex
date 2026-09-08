// External test package: runs the shared backend-parity suite
// (internal/bus/bustest, issue #15) against the in-memory bus. The
// JetStream backend runs the identical suite against a live
// nats-server (see internal/bus/natsbus/natsbus_test.go) — if the two
// ever diverge, natsbus is fixed.
package bus_test

import (
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus/bustest"
)

func TestParitySuiteMemory(t *testing.T) {
	bustest.RunSuite(t, "memory", func(t *testing.T) (bustest.Bus, func()) {
		return bus.New(), func() {}
	}, bustest.SuiteOptions{RingCap: true})
}

// Compile-time proof that the in-memory bus satisfies the interface
// consumers depend on.
var _ bus.BusI = (*bus.Bus)(nil)
