package state_test

// Tests for the exported canonical comparison (issue #72): the API
// layer gates EventUpdated publication on state.SpecLabelsEqual so its
// no-op decision is exactly the store's generation-bump/audit decision.
// These tests pin the comparison semantics that contract relies on.

import (
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func resWith(spec map[string]any, labels map[string]string) *state.Resource {
	return &state.Resource{Spec: spec, Labels: labels}
}

func TestSpecLabelsEqual(t *testing.T) {
	// Canonical JSON: map key order can never matter, at any nesting
	// depth.
	a := resWith(map[string]any{
		"image": "app:1", "replicas": float64(3),
		"env": map[string]any{"region": "eu", "zone": "b"},
	}, nil)
	b := resWith(map[string]any{
		"env":      map[string]any{"zone": "b", "region": "eu"},
		"replicas": float64(3), "image": "app:1",
	}, nil)
	if !state.SpecLabelsEqual(a, b) {
		t.Fatal("same spec in different key order must compare equal")
	}

	// Scalar and nested value changes are changes.
	changed := resWith(map[string]any{
		"image": "app:2", "replicas": float64(3),
		"env": map[string]any{"region": "eu", "zone": "b"},
	}, nil)
	if state.SpecLabelsEqual(a, changed) {
		t.Fatal("different scalar value must not compare equal")
	}
	nested := resWith(map[string]any{
		"image": "app:1", "replicas": float64(3),
		"env": map[string]any{"region": "eu", "zone": "c"},
	}, nil)
	if state.SpecLabelsEqual(a, nested) {
		t.Fatal("different nested value must not compare equal")
	}
	extra := resWith(map[string]any{
		"image": "app:1", "replicas": float64(3), "extra": "k",
		"env": map[string]any{"region": "eu", "zone": "b"},
	}, nil)
	if state.SpecLabelsEqual(a, extra) {
		t.Fatal("extra spec key must not compare equal")
	}

	// Labels are plain map equality; nil and empty are equivalent.
	l1 := resWith(map[string]any{"image": "app:1"}, map[string]string{"team": "payments"})
	l2 := resWith(map[string]any{"image": "app:1"}, map[string]string{"team": "platform"})
	if state.SpecLabelsEqual(l1, l2) {
		t.Fatal("different label values must not compare equal")
	}
	l3 := resWith(map[string]any{"image": "app:1"}, map[string]string{"team": "payments", "tier": "gold"})
	if state.SpecLabelsEqual(l1, l3) {
		t.Fatal("extra label must not compare equal")
	}
	if !state.SpecLabelsEqual(l1, resWith(map[string]any{"image": "app:1"}, map[string]string{"team": "payments"})) {
		t.Fatal("identical labels must compare equal")
	}
	if !state.SpecLabelsEqual(resWith(map[string]any{"image": "app:1"}, nil),
		resWith(map[string]any{"image": "app:1"}, map[string]string{})) {
		t.Fatal("nil and empty label sets must compare equal")
	}

	// Missing vs present spec is a change (canonical JSON "null" vs
	// "{}"); unreachable through the API (Validate requires spec) but
	// pinned so the canonical form stays explicit.
	if state.SpecLabelsEqual(resWith(nil, nil), resWith(map[string]any{}, nil)) {
		t.Fatal("nil spec and empty spec must not compare equal")
	}

	// The predicate is symmetric.
	if state.SpecLabelsEqual(a, changed) != state.SpecLabelsEqual(changed, a) {
		t.Fatal("comparison must be symmetric")
	}
}
