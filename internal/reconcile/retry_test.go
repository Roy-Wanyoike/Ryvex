package reconcile

import (
	"testing"
	"time"
)

func TestBackoffExponentialGrowthCapped(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 8, BaseDelay: time.Second, MaxDelay: 30 * time.Second}
	cases := []struct {
		n    int
		want time.Duration
	}{
		{1, 1 * time.Second},  // wait before attempt 2
		{2, 2 * time.Second},  // attempt 3
		{3, 4 * time.Second},  // attempt 4
		{5, 16 * time.Second}, // attempt 6
		{6, 30 * time.Second}, // capped
		{50, 30 * time.Second},
		{1000, 30 * time.Second}, // shift-guarded, no overflow
		{0, 1 * time.Second},     // clamped to the first wait
	}
	for _, c := range cases {
		if got := Backoff(p, c.n); got != c.want {
			t.Errorf("Backoff(p, %d) = %v, want %v", c.n, got, c.want)
		}
	}
}

func TestRetryPolicySanitized(t *testing.T) {
	// Zero policy collapses to the defaults.
	got := RetryPolicy{}.sanitized()
	if got.MaxAttempts != 4 || got.BaseDelay != time.Second || got.MaxDelay != 30*time.Second {
		t.Fatalf("zero policy = %+v, want defaults", got)
	}
	// Nonsense collapses to the defaults, not to surprises.
	got = RetryPolicy{MaxAttempts: -3, BaseDelay: 0, MaxDelay: time.Millisecond}.sanitized()
	if got.MaxAttempts != 4 || got.BaseDelay != time.Second || got.MaxDelay != 30*time.Second {
		t.Fatalf("negative policy = %+v", got)
	}
	// A sane override survives.
	got = RetryPolicy{MaxAttempts: 7, BaseDelay: 250 * time.Millisecond, MaxDelay: 2 * time.Second}.sanitized()
	if got.MaxAttempts != 7 || got.BaseDelay != 250*time.Millisecond || got.MaxDelay != 2*time.Second {
		t.Fatalf("sane policy mangled: %+v", got)
	}
}

func TestAttemptBookEpisodeLifecycle(t *testing.T) {
	b := newAttemptBook()

	// Unknown resources are always due.
	if !b.due("a", 1) {
		t.Fatal("fresh resource must be due")
	}

	// First attempt: record returns 1 and scheduling sets a future due.
	if n := b.record("a", 1); n != 1 {
		t.Fatalf("first record = %d, want 1", n)
	}
	b.schedule("a", 1, 50*time.Millisecond)
	if b.due("a", 1) {
		t.Fatal("resource inside its backoff window must not be due")
	}
	if n := b.record("a", 1); n != 2 {
		t.Fatalf("second record = %d, want 2", n)
	}

	// The window elapses.
	time.Sleep(60 * time.Millisecond)
	if !b.due("a", 1) {
		t.Fatal("resource must be due after the backoff window")
	}

	// A new generation resets the counter to a fresh budget.
	if n := b.record("a", 2); n != 1 {
		t.Fatalf("record across generations = %d, want 1", n)
	}

	// begin() on a fresh generation also resets.
	b.begin("a", 3)
	if n := b.record("a", 3); n != 1 {
		t.Fatalf("record after begin = %d, want 1", n)
	}

	// clear drops the episode.
	b.clear("a")
	if !b.due("a", 3) {
		t.Fatal("cleared resource must be due")
	}
	if n := b.record("a", 3); n != 1 {
		t.Fatalf("record after clear = %d, want 1", n)
	}
}
