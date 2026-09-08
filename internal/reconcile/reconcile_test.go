package reconcile

import (
	"context"
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
