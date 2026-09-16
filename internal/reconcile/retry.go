package reconcile

import (
	"sync"
	"time"
)

// RetryPolicy governs actuation retries per resource kind (issue #80).
// The reconciler applies it to every classified-Transient or
// Unavailable actuator failure: the resource sits Degraded between
// attempts and transitions to Failed once the budget is exhausted.
// Permanent failures skip the policy entirely (retrying them is
// lying). The policy lives on the controller side on purpose: provider
// authors classify failures, the reconciler owns what they mean.
type RetryPolicy struct {
	// MaxAttempts is the total number of Plan+Apply attempts per
	// resource per generation episode (including the first). The
	// budget is kept in memory: a daemon restart restarts the episode,
	// and the next spec generation opens a fresh one.
	MaxAttempts int
	// BaseDelay is the wait before the second attempt.
	BaseDelay time.Duration
	// MaxDelay caps the exponential growth.
	MaxDelay time.Duration
}

// DefaultRetryPolicy is the fallback for kinds without an override:
// 4 attempts at 1s/2s/4s — enough to ride out a blip, short enough
// that Failed means something within a normal scan interval budget.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 4, BaseDelay: 1 * time.Second, MaxDelay: 30 * time.Second}
}

// sanitized fills unset fields with the defaults: a zero/negative
// attempt budget means "policy not really specified" and gets the
// defaults (an explicit single-attempt policy is MaxAttempts: 1).
func (p RetryPolicy) sanitized() RetryPolicy {
	def := DefaultRetryPolicy()
	if p.BaseDelay <= 0 {
		p.BaseDelay = def.BaseDelay
	}
	if p.MaxDelay < p.BaseDelay {
		p.MaxDelay = def.MaxDelay
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = def.MaxAttempts
	}
	return p
}

// Backoff returns the wait before attempt n+1 after the n-th failure
// (n starts at 1): BaseDelay × 2^(n-1), capped at MaxDelay. The growth
// is deterministic (no jitter) so tests and operators can reason about
// exact schedules; contention smoothing is a non-goal at reference
// scale.
func Backoff(p RetryPolicy, n int) time.Duration {
	p = p.sanitized()
	if n < 1 {
		n = 1
	}
	// Guard the shift: beyond ~20 doublings any sane cap has long
	// since clipped the value, and overflow would wrap negative.
	const maxShift = 20
	shift := n - 1
	if shift > maxShift {
		shift = maxShift
	}
	d := p.BaseDelay * (1 << uint(shift))
	if d > p.MaxDelay {
		d = p.MaxDelay
	}
	return d
}

// attemptBook tracks per-resource retry state for actuated kinds: the
// spec generation the episode belongs to, how many attempts have been
// made, and when the next attempt is due. It is guarded by one mutex —
// contention is negligible at reconcile cadences.
type attemptBook struct {
	mu   sync.Mutex
	byID map[string]*attemptState
}

type attemptState struct {
	gen  int64
	n    int
	next time.Time
}

func newAttemptBook() *attemptBook {
	return &attemptBook{byID: map[string]*attemptState{}}
}

// begin (re)opens an episode for id: if the recorded generation is
// stale the attempt counter resets, so a fresh spec generation always
// gets a full retry budget. Called on every actuated reconcile pass.
func (b *attemptBook) begin(id string, gen int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.byID[id]
	if !ok || st.gen != gen {
		b.byID[id] = &attemptState{gen: gen}
	}
}

// record bumps the attempt counter for id's generation and returns the
// new count. A generation mismatch (spec changed mid-episode) starts a
// fresh counter.
func (b *attemptBook) record(id string, gen int64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.byID[id]
	if !ok || st.gen != gen {
		st = &attemptState{gen: gen}
		b.byID[id] = st
	}
	st.n++
	return st.n
}

// schedule records when the next attempt for id's generation may run.
func (b *attemptBook) schedule(id string, gen int64, delay time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.byID[id]
	if !ok || st.gen != gen {
		st = &attemptState{gen: gen}
		b.byID[id] = st
	}
	st.next = time.Now().Add(delay)
}

// due reports whether an attempt for id's current generation may run
// now. No recorded state (first attempt, or a daemon restart) is due;
// a Degraded resource inside its backoff window is not.
func (b *attemptBook) due(id string, gen int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.byID[id]
	if !ok || st.gen != gen {
		return true
	}
	return !time.Now().Before(st.next)
}

// clear drops the episode: the resource reached Ready or Failed, so
// the next failure (drift re-apply, new generation) starts fresh.
func (b *attemptBook) clear(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byID, id)
}
