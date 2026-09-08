package pgstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
	"github.com/Roy-Wanyoike/Ryvex/internal/state/pgstore"
	"github.com/Roy-Wanyoike/Ryvex/internal/state/statetest"
)

// pgDSNEnv gates the live-Postgres tests. When unset, the parity suite
// is skipped (go test ./... stays green on machines without a DB).
const pgDSNEnv = "RYVEX_TEST_PG_DSN"

var (
	migrateOnce sync.Once
	migrateErr  error
)

// newPGStore is the parity-suite harness: it connects to the live
// Postgres, applies migrations (idempotently exercising Migrate) and
// hands every test an EMPTY table set, matching the fresh in-memory
// store the reference runner provides.
func newPGStore(t *testing.T) statetest.Store {
	t.Helper()
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres parity suite", pgDSNEnv)
	}

	// Migrate once per process; individual suites still call Migrate
	// again to prove idempotency.
	migrateOnce.Do(func() {
		st, err := pgstore.NewStore(dsn)
		if err != nil {
			t.Fatalf("initial connect: %v", err)
		}
		defer st.Close()
		migrateErr = st.Migrate(context.Background())
	})
	if migrateErr != nil {
		t.Fatalf("migrate: %v", migrateErr)
	}

	// Wipe state so every suite case starts from an empty store.
	clean, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open cleanup pool: %v", err)
	}
	if _, err := clean.Exec(`TRUNCATE resources, audit RESTART IDENTITY`); err != nil {
		clean.Close()
		t.Fatalf("truncate: %v", err)
	}
	clean.Close()

	st, err := pgstore.NewStore(dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// TestPGStoreParitySuite runs the shared behavioral suite against the
// live Postgres. Every case must behave identically to the in-memory
// reference store.
func TestPGStoreParitySuite(t *testing.T) {
	statetest.RunSuite(t, newPGStore)
}

// TestMigrateIdempotent: Migrate can run repeatedly (fresh DB, again
// on the same store, and from a second store) and always leaves the
// schema at the latest version with data intact.
func TestMigrateIdempotent(t *testing.T) {
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres parity suite", pgDSNEnv)
	}

	st, err := pgstore.NewStore(dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	v1, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v1 == 0 {
		t.Fatalf("schema version must be > 0 after migrate, got %d", v1)
	}

	// leave a marker row so we can prove migrations don't touch data
	r, err := st.CreateResource(&state.Resource{
		Kind: "Application", Org: "mig", Project: "core", Env: "prod", Name: "probe",
		Labels: map[string]string{"managed-by": "ryvex"},
		Spec:   map[string]any{"replicas": 1},
	}, state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create probe: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("third migrate: %v", err)
	}
	v2, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version after re-migrate: %v", err)
	}
	if v2 != v1 {
		t.Fatalf("re-migrate changed schema version %d -> %d", v1, v2)
	}
	got, err := st.GetResource(r.ID)
	if err != nil || got.Name != "probe" {
		t.Fatalf("re-migrate must preserve data: %+v err=%v", got, err)
	}

	// a second Store on the same database must also be a no-op
	st2, err := pgstore.NewStore(dsn)
	if err != nil {
		t.Fatalf("connect 2: %v", err)
	}
	defer st2.Close()
	if err := st2.Migrate(ctx); err != nil {
		t.Fatalf("migrate from second store: %v", err)
	}
	if _, err := st2.GetResource(r.ID); err != nil {
		t.Fatalf("second store cannot read: %v", err)
	}
}

// TestNewStoreBadDSN needs no live database: bad DSNs must fail fast.
func TestNewStoreBadDSN(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := pgstore.NewStore("  "); err == nil {
			t.Fatal("empty DSN must be rejected")
		}
	})
	t.Run("unroutable host", func(t *testing.T) {
		// connection refused -> fail fast inside NewStore's ping
		dsn := "postgres://postgres@127.0.0.1:1/none?sslmode=disable&connect_timeout=2"
		start := time.Now()
		_, err := pgstore.NewStore(dsn)
		if err == nil {
			t.Fatal("unroutable DSN must be rejected")
		}
		if elapsed := time.Since(start); elapsed > 8*time.Second {
			t.Fatalf("connect failure took too long: %v", elapsed)
		}
	})
	t.Run("malformed dsn", func(t *testing.T) {
		if _, err := pgstore.NewStore("postgres://postgres@127.0.0.1:99999/db?sslmode=disable"); err == nil {
			t.Fatal("malformed DSN must be rejected")
		}
	})
}

// TestCloseIsIdempotentEnough: double Close must not panic.
func TestCloseIsIdempotentEnough(t *testing.T) {
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres parity suite", pgDSNEnv)
	}
	st, err := pgstore.NewStore(dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	// Ensure sentinel errors still compare by identity after import.
	if !errors.Is(state.ErrNotFound, state.ErrNotFound) {
		t.Fatal("errors.Is sanity check failed")
	}
}
