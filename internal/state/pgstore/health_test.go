package pgstore

// Dependency-down tests (issue #71): when Postgres is unreachable,
// every formerly-swallowing read path must propagate an error —
// Count never reports a healthy empty store, ListAudit never
// masquerades as an empty compliance log, and Ping fails so /readyz
// can hold the pod out of rotation.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// newDeadStore opens a pool against an unroutable address. sql.Open
// does not connect eagerly, so constructing the store succeeds — the
// failure only surfaces when a query is actually attempted, exactly
// like a database dying mid-flight.
func newDeadStore(t *testing.T) *Store {
	t.Helper()
	// Port 1 on loopback refuses instantly; connect_timeout bounds any
	// retry behavior so the test stays fast.
	db, err := sql.Open("postgres", "postgres://postgres@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open dead pool: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Store{db: db}
}

func TestDependencyDownUnroutableDSN(t *testing.T) {
	s := newDeadStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err == nil {
		t.Fatal("Ping on an unreachable database must fail")
	}
	if n, err := s.Count(); err == nil || n != 0 {
		t.Fatalf("Count on dead DB = (%d, %v), want (0, error)", n, err)
	}
	if snap, err := s.CountByKindPhase(); err == nil || snap != nil {
		t.Fatalf("CountByKindPhase on dead DB = (%v, %v), want (nil, error)", snap, err)
	}
	if entries, err := s.ListAudit(state.AuditOptions{}); err == nil || entries != nil {
		t.Fatalf("ListAudit on dead DB = (%v, %v), want (nil, error)", entries, err)
	}
	if e, err := s.AppendAudit(state.AuditEntry{Actor: "t", Action: "webhook_failed"}); err == nil || e.ID != "" {
		t.Fatalf("AppendAudit on dead DB = (%+v, %v), want (zero entry, error)", e, err)
	}
}

// TestDependencyDownClosedDB exercises the "database went away after a
// healthy boot" path: Close the live pool, then every query must fail.
// Needs a live Postgres (RYVEX_TEST_PG_DSN), like the parity suite.
func TestDependencyDownClosedDB(t *testing.T) {
	dsn := os.Getenv("RYVEX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("RYVEX_TEST_PG_DSN not set; skipping closed-DB dependency-down test")
	}
	st, err := NewStore(dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("Ping must succeed before Close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := st.Ping(ctx); err == nil {
		t.Fatal("Ping after Close must fail")
	}
	if _, err := st.Count(); err == nil {
		t.Fatal("Count after Close must fail")
	}
	if _, err := st.ListAudit(state.AuditOptions{}); err == nil {
		t.Fatal("ListAudit after Close must fail")
	}
	if _, err := st.AppendAudit(state.AuditEntry{Actor: "t", Action: "webhook_failed"}); err == nil {
		t.Fatal("AppendAudit after Close must fail")
	}
}
