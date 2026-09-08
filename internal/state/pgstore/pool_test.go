package pgstore

import (
	"testing"
)

// TestPoolLimitsFromEnv pins the defensive env parsing behind the
// connection-pool bounds (issue #39): only positive integers are
// honoured, everything else keeps the default, and the idle cap never
// exceeds the open cap. No database needed — this is pure config.
func TestPoolLimitsFromEnv(t *testing.T) {
	const (
		openEnv = "RYVEX_PG_MAX_OPEN_CONNS"
		idleEnv = "RYVEX_PG_MAX_IDLE_CONNS"
	)

	tests := []struct {
		name       string
		open, idle string
		wantOpen   int
		wantIdle   int
	}{
		{name: "unset keeps defaults", open: "", idle: "", wantOpen: 25, wantIdle: 10},
		{name: "garbage keeps defaults", open: "banana", idle: "12 bananas", wantOpen: 25, wantIdle: 10},
		{name: "zero and negative keep defaults", open: "0", idle: "-3", wantOpen: 25, wantIdle: 10},
		{name: "valid overrides honoured", open: "40", idle: "20", wantOpen: 40, wantIdle: 20},
		{name: "whitespace tolerated", open: " 30 ", idle: "\t8", wantOpen: 30, wantIdle: 8},
		{name: "idle clamped to open", open: "5", idle: "50", wantOpen: 5, wantIdle: 5},
		{name: "float is garbage", open: "12.5", idle: "1e2", wantOpen: 25, wantIdle: 10},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(openEnv, tc.open)
			t.Setenv(idleEnv, tc.idle)
			gotOpen, gotIdle := poolLimitsFromEnv()
			if gotOpen != tc.wantOpen || gotIdle != tc.wantIdle {
				t.Fatalf("poolLimitsFromEnv() = (%d, %d), want (%d, %d)",
					gotOpen, gotIdle, tc.wantOpen, tc.wantIdle)
			}
		})
	}
}
