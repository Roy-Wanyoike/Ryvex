package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func mkStore(t *testing.T) (*state.Store, *bus.Bus) {
	t.Helper()
	return state.NewStore(), bus.New()
}

func mkRes(kind, name string) *state.Resource {
	return &state.Resource{
		Kind: kind, Org: "acme", Project: "core", Env: "prod", Name: name,
		Spec: map[string]any{"image": "demo:1"},
	}
}

// waitPhase polls until the resource reaches the wanted phase.
func waitPhase(t *testing.T, s *state.Store, id, phase string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, err := s.GetResource(id)
		if err == nil && r.Status.Phase == phase {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("resource %s never reached phase %s", id, phase)
}

func TestConvergesToReady(t *testing.T) {
	store, b := mkStore(t)
	r, err := store.CreateResource(mkRes(state.KindApplication, "web"), state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := New(store, b, Options{Interval: 20 * time.Millisecond, Concurrency: 2, Logger: slog.Default()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, r.ID, state.PhaseReady)

	got, _ := store.GetResource(r.ID)
	if got.Status.ObservedGen != got.Generation {
		t.Fatalf("observed generation not stamped: %+v", got.Status)
	}
	if got.Status.Message == "" {
		t.Fatalf("expected a status message")
	}
}

func TestStatusChangesPublished(t *testing.T) {
	store, b := mkStore(t)
	_, _ = store.CreateResource(mkRes(state.KindCache, "sessions"), state.WriteOptions{Actor: "test"})

	var seen int
	done := make(chan struct{})
	sub := b.Subscribe("ryvex.resource.acme.cache.status_changed", func(e bus.Event) {
		if e.Phase == state.PhaseReady {
			seen++
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})
	defer sub.Cancel()

	rec := New(store, b, Options{Interval: 15 * time.Millisecond, Concurrency: 1, Logger: slog.Default()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("never observed Ready on the bus (saw %d)", seen)
	}
}

func TestTriggerForceImmediateReconcile(t *testing.T) {
	store, b := mkStore(t)
	r, _ := store.CreateResource(mkRes(state.KindBucket, "assets"), state.WriteOptions{Actor: "test"})

	rec := New(store, b, Options{Interval: time.Hour, Concurrency: 1, Logger: slog.Default()}) // slow scan
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	rec.Trigger(r.ID)
	waitPhase(t, store, r.ID, state.PhaseReady)
}

func TestSecretsConvergeFast(t *testing.T) {
	store, b := mkStore(t)
	created, _ := store.CreateResource(mkRes(state.KindSecret, "vault-token"), state.WriteOptions{Actor: "test"})
	rec := New(store, b, Options{Interval: 10 * time.Millisecond, Concurrency: 1, Logger: slog.Default()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, created.ID, state.PhaseReady)
	got, _ := store.GetResource(created.ID)
	if got.Status.Message != "secret sealed and mounted" {
		t.Fatalf("unexpected message: %q", got.Status.Message)
	}
}

// TestScanPagesPastListLimit proves the scan converges more resources
// than a single list page can return (issue #37). The store clamps
// ListOptions.Limit to 200 and returns a next cursor beyond that, so
// before pagination resources #201+ were never queued and sat Pending
// forever.
func TestScanPagesPastListLimit(t *testing.T) {
	store, b := mkStore(t)

	const total = 250 // one full page (200) plus a tail the old scan never saw
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		r, err := store.CreateResource(mkRes(state.KindApplication, fmt.Sprintf("svc-%03d", i)), state.WriteOptions{Actor: "test"})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		ids = append(ids, r.ID)
	}
	if store.Count() != total {
		t.Fatalf("seeded %d resources, want %d", store.Count(), total)
	}

	rec := New(store, b, Options{Interval: 5 * time.Millisecond, Concurrency: 4, Logger: slog.Default()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	// The trigger queue (cap 128) drops sends while saturated, so the
	// tail is picked up by subsequent scans; poll until the whole
	// inventory converges instead of waiting on a single resource.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := 0
		for _, id := range ids {
			if r, err := store.GetResource(id); err == nil && r.Status.Phase == state.PhaseReady {
				ready++
			}
		}
		if ready == total {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d resources converged to Ready; the scan is not reaching the tail", ready, total)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
