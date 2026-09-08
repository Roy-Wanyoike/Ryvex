package pgstore

import (
	"context"
	"database/sql"
	"fmt"
)

// migration is one versioned schema step. Each runs exactly once,
// inside a transaction that also records the version.
type migration struct {
	version int
	name    string
	body    string
}

// migrations is append-only: never edit an applied migration, add a
// new file under migrations/ and register it here.
var migrations = []migration{
	{version: 1, name: "init", body: migration0001},
}

// Migrate applies all pending schema migrations. It is idempotent and
// safe to call on every boot: applied versions are recorded in
// schema_migrations and skipped.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer PRIMARY KEY,
			name       text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("pgstore: ensure schema_migrations: %w", err)
	}

	for _, m := range migrations {
		var applied bool
		err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			m.version).Scan(&applied)
		if err != nil {
			return fmt.Errorf("pgstore: check migration %d: %w", m.version, err)
		}
		if applied {
			continue
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("pgstore: begin migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, m.body); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("pgstore: apply migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
			m.version, m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("pgstore: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("pgstore: commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

// SchemaVersion reports the highest applied migration version. Used by
// tests and boot diagnostics; 0 means an unmigrated database.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}
