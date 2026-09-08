// Package pgstore is the durable Postgres implementation of the
// Ryvex state store. It mirrors the semantics of the in-memory
// reference store in internal/state exactly — validation order,
// compare-and-swap updates, no-op detection, reconciler-owned status,
// audit trail and cursor pagination — and is held to the same
// behavioral suite (internal/state/statetest) on every change.
//
// Driver: github.com/lib/pq (stdlib database/sql style, the most
// conservative choice). The first Ryvex external dependency.
package pgstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Store is a Postgres-backed state.Store. Create one with NewStore,
// call Migrate once at boot, then use it anywhere a state.Backend is
// expected. The zero value is not usable.
type Store struct {
	db *sql.DB
}

// NewStore opens a connection pool against dsn and verifies
// connectivity (fail fast at boot). The caller owns schema setup via
// Migrate and must call Close on shutdown.
func NewStore(dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("pgstore: DSN is empty (pass --dsn or set RYVEX_DATABASE_URL)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pgstore: connect: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the connection pool.
func (s *Store) Close() error { return s.db.Close() }

// ctx bounds every statement so a wedged database cannot hang the
// control plane indefinitely.
func (s *Store) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// execer is satisfied by both *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const resourceCols = `id, org, project, env, kind, name, generation, labels, spec,
        phase, message, observed_gen, status_updated_at, created_at, updated_at`

func nowMicro() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// scanResource hydrates one resources row.
func scanResource(sc interface{ Scan(...any) error }) (*state.Resource, error) {
	var (
		r        state.Resource
		labelsB  []byte
		specB    []byte
		statusUp sql.NullTime
	)
	if err := sc.Scan(&r.ID, &r.Org, &r.Project, &r.Env, &r.Kind, &r.Name,
		&r.Generation, &labelsB, &specB, &r.Status.Phase, &r.Status.Message,
		&r.Status.ObservedGen, &statusUp, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	// jsonb "null" (nil labels) leaves the map nil; "{}" yields an
	// empty non-nil map — matching the reference store exactly.
	if len(labelsB) > 0 {
		if err := json.Unmarshal(labelsB, &r.Labels); err != nil {
			return nil, fmt.Errorf("pgstore: decode labels: %w", err)
		}
	}
	if len(specB) > 0 {
		if err := json.Unmarshal(specB, &r.Spec); err != nil {
			return nil, fmt.Errorf("pgstore: decode spec: %w", err)
		}
	}
	r.Status.UpdatedAt = statusUp.Time
	return &r, nil
}

// newID mints an opaque resource handle: r-<16 hex>, same shape as the
// reference store.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}

// newAuditID mints an audit handle: a-<16 hex>.
func newAuditID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "a-" + hex.EncodeToString(b[:])
}

// isUniqueViolation reports whether err is a Postgres unique_violation
// (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

// insertAudit appends one audit entry on the given executor (tx or db).
func insertAudit(ctx context.Context, ex execer, e state.AuditEntry) error {
	_, err := ex.ExecContext(ctx, `
                INSERT INTO audit (id, ts, actor, action, resource_id, kind, logical_key, generation, reason)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.ID, e.Time, e.Actor, e.Action, e.ResourceID, e.Kind, e.LogicalKey, e.Generation, e.Reason)
	return err
}

// auditFor builds a store-generated audit entry for a resource.
// Note: WriteOptions.Reason is intentionally NOT recorded here — the
// reference store drops it too.
func auditFor(actor, action string, r *state.Resource, ts time.Time) state.AuditEntry {
	return state.AuditEntry{
		ID:         newAuditID(),
		Time:       ts,
		Actor:      actor,
		Action:     action,
		ResourceID: r.ID,
		Kind:       r.Kind,
		LogicalKey: r.LogicalKey(),
		Generation: r.Generation,
	}
}

// CreateResource validates first (before any state is touched), then
// inserts the resource plus its "created" audit entry in one
// transaction. A taken logical address maps to state.ErrAlreadyExists.
// Defaults mirror the reference store: id r-<16hex>, generation 1,
// phase Pending when unset, observed generation 0.
func (s *Store) CreateResource(r *state.Resource, opts state.WriteOptions) (*state.Resource, error) {
	if r == nil {
		return nil, state.ErrValidation
	}
	if opts.Actor == "" {
		opts.Actor = "anonymous"
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}

	now := nowMicro()
	stored := r.DeepCopy()
	stored.ID = newID()
	stored.Generation = 1
	stored.CreatedAt = now
	stored.UpdatedAt = now
	if stored.Status.Phase == "" {
		stored.Status.Phase = state.PhasePending
	}
	stored.Status.ObservedGen = 0
	stored.Status.UpdatedAt = now

	labels, err := json.Marshal(stored.Labels) // nil -> "null", {} -> "{}"
	if err != nil {
		return nil, fmt.Errorf("pgstore: encode labels: %w", err)
	}
	spec, err := json.Marshal(stored.Spec)
	if err != nil {
		return nil, fmt.Errorf("pgstore: encode spec: %w", err)
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("pgstore: create begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
                INSERT INTO resources (`+resourceCols+`)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		stored.ID, stored.Org, stored.Project, stored.Env, stored.Kind, stored.Name,
		stored.Generation, labels, spec, stored.Status.Phase, stored.Status.Message,
		stored.Status.ObservedGen, nullTime(stored.Status.UpdatedAt),
		stored.CreatedAt, stored.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, state.ErrAlreadyExists
		}
		return nil, fmt.Errorf("pgstore: create insert: %w", err)
	}
	if err := insertAudit(ctx, tx, auditFor(opts.Actor, "created", stored, now)); err != nil {
		return nil, fmt.Errorf("pgstore: create audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("pgstore: create commit: %w", err)
	}
	return stored.DeepCopy(), nil
}

// GetResource fetches by opaque ID.
func (s *Store) GetResource(id string) (*state.Resource, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	r, err := scanResource(s.db.QueryRowContext(ctx,
		`SELECT `+resourceCols+` FROM resources WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: get %s: %w", id, err)
	}
	return r, nil
}

// GetByLogicalKey fetches by org/project/env/kind/name address.
func (s *Store) GetByLogicalKey(org, project, env, kind, name string) (*state.Resource, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	r, err := scanResource(s.db.QueryRowContext(ctx, `
                SELECT `+resourceCols+` FROM resources
                WHERE org=$1 AND project=$2 AND env=$3 AND kind=$4 AND name=$5`,
		org, project, env, kind, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: get %s/%s/%s/%s/%s: %w", org, project, env, kind, name, err)
	}
	return r, nil
}

// ListResources returns a filtered page ordered by (created_at, id),
// paginated with the same base64 offset cursor as the reference store.
func (s *Store) ListResources(o state.ListOptions) ([]*state.Resource, string, error) {
	offset := 0
	if o.Cursor != "" {
		n, err := state.DecodeCursor(o.Cursor)
		if err != nil {
			return nil, "", err
		}
		offset = n
	}
	limit := o.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	where := make([]string, 0, 4)
	args := make([]any, 0, 6)
	add := func(col string, v string) {
		args = append(args, v)
		where = append(where, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if o.Org != "" {
		add("org", o.Org)
	}
	if o.Project != "" {
		add("project", o.Project)
	}
	if o.Env != "" {
		add("env", o.Env)
	}
	if o.Kind != "" {
		add("kind", o.Kind)
	}
	args = append(args, limit+1, offset) // fetch one extra to detect a next page
	query := `SELECT ` + resourceCols + ` FROM resources`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += fmt.Sprintf(` ORDER BY created_at, id LIMIT $%d OFFSET $%d`, len(args)-1, len(args))

	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("pgstore: list: %w", err)
	}
	defer rows.Close()

	page := make([]*state.Resource, 0, limit)
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, "", fmt.Errorf("pgstore: list scan: %w", err)
		}
		page = append(page, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("pgstore: list rows: %w", err)
	}
	next := ""
	if len(page) > limit {
		next = state.EncodeCursor(offset + limit)
		page = page[:limit]
	}
	return page, next, nil
}

// UpdateResource mutates the resource via fn under a CAS check, all in
// one transaction: the row is locked, ExpectedGeneration is verified,
// fn runs on a copy, the result is validated, and a single guarded
// UPDATE persists it. Generation advances only when spec or labels
// actually changed (JSON equality); status is whatever fn leaves
// behind (users never send it — the API layer owns that rule), and a
// no-op update rewrites updated_at without bumping the generation and
// without an "updated" audit entry.
func (s *Store) UpdateResource(id string, fn func(*state.Resource) error, o state.UpdateOptions) (*state.Resource, error) {
	if o.Actor == "" {
		o.Actor = "anonymous"
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("pgstore: update begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := scanResource(tx.QueryRowContext(ctx,
		`SELECT `+resourceCols+` FROM resources WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: update select %s: %w", id, err)
	}
	if o.ExpectedGeneration != 0 && o.ExpectedGeneration != cur.Generation {
		return nil, state.ErrConflict
	}

	work := cur.DeepCopy()
	if err := fn(work); err != nil {
		return nil, err
	}
	if err := work.Validate(); err != nil {
		return nil, err
	}

	changed := !specLabelsEqual(cur, work)
	newGen := cur.Generation
	if changed {
		newGen = cur.Generation + 1
	}
	now := nowMicro()
	work.Generation = newGen
	work.UpdatedAt = now

	labels, err := json.Marshal(work.Labels)
	if err != nil {
		return nil, fmt.Errorf("pgstore: encode labels: %w", err)
	}
	spec, err := json.Marshal(work.Spec)
	if err != nil {
		return nil, fmt.Errorf("pgstore: encode spec: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
                UPDATE resources SET
                        org=$2, project=$3, env=$4, kind=$5, name=$6, generation=$7,
                        labels=$8, spec=$9, phase=$10, message=$11, observed_gen=$12,
                        status_updated_at=$13, created_at=$14, updated_at=$15
                WHERE id=$1 AND generation=$16`,
		id, work.Org, work.Project, work.Env, work.Kind, work.Name,
		work.Generation, labels, spec, work.Status.Phase, work.Status.Message,
		work.Status.ObservedGen, nullTime(work.Status.UpdatedAt),
		work.CreatedAt, work.UpdatedAt, cur.Generation)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, state.ErrAlreadyExists
		}
		return nil, fmt.Errorf("pgstore: update %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// The guarded UPDATE hit nothing: either the row vanished
		// concurrently (ErrNotFound) or a writer moved the
		// generation (ErrConflict).
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM resources WHERE id = $1)`, id).Scan(&exists); err != nil {
			return nil, fmt.Errorf("pgstore: update probe %s: %w", id, err)
		}
		if !exists {
			return nil, state.ErrNotFound
		}
		return nil, state.ErrConflict
	}
	if changed {
		if err := insertAudit(ctx, tx, auditFor(o.Actor, "updated", work, now)); err != nil {
			return nil, fmt.Errorf("pgstore: update audit: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("pgstore: update commit: %w", err)
	}
	return work.DeepCopy(), nil
}

// UpdateStatus is the reconciler-owned status path: it stamps the
// phase, message and observed generation (= spec generation) and
// always records a "status_changed" audit entry. It never bumps the
// spec generation.
func (s *Store) UpdateStatus(id string, phase, message string, actor state.WriteOptions) error {
	if actor.Actor == "" {
		actor.Actor = "reconciler"
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore: status begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := scanResource(tx.QueryRowContext(ctx,
		`SELECT `+resourceCols+` FROM resources WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return state.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("pgstore: status select %s: %w", id, err)
	}

	now := nowMicro()
	changed := cur.Status.Phase != phase || cur.Status.Message != message
	stUp, upAt := cur.Status.UpdatedAt, cur.UpdatedAt
	if changed {
		stUp, upAt = now, now
	}
	if _, err := tx.ExecContext(ctx, `
                UPDATE resources SET phase=$1, message=$2, observed_gen=generation,
                        status_updated_at=$3, updated_at=$4
                WHERE id=$5`,
		phase, message, nullTime(stUp), upAt, id); err != nil {
		return fmt.Errorf("pgstore: status update %s: %w", id, err)
	}
	if err := insertAudit(ctx, tx, auditFor(actor.Actor, "status_changed", cur, now)); err != nil {
		return fmt.Errorf("pgstore: status audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: status commit: %w", err)
	}
	return nil
}

// DeleteResource removes the resource and writes the "deleted" audit
// entry in one transaction.
func (s *Store) DeleteResource(id string, opts state.WriteOptions) error {
	if opts.Actor == "" {
		opts.Actor = "anonymous"
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore: delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := scanResource(tx.QueryRowContext(ctx,
		`SELECT `+resourceCols+` FROM resources WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return state.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("pgstore: delete select %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE id = $1`, id); err != nil {
		return fmt.Errorf("pgstore: delete %s: %w", id, err)
	}
	if err := insertAudit(ctx, tx, auditFor(opts.Actor, "deleted", cur, nowMicro())); err != nil {
		return fmt.Errorf("pgstore: delete audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: delete commit: %w", err)
	}
	return nil
}

// Count returns the number of stored resources (used by /healthz).
// A database error reports 0 — the signature has no error return.
func (s *Store) Count() int {
	ctx, cancel := s.ctx()
	defer cancel()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM resources`).Scan(&n); err != nil {
		return 0
	}
	return n
}

// CountByKindPhase returns the per-kind/per-phase snapshot backing the
// ryvex_resources metrics gauge.
func (s *Store) CountByKindPhase() map[string]map[string]int64 {
	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, phase, COUNT(*) FROM resources GROUP BY kind, phase`)
	if err != nil {
		return map[string]map[string]int64{}
	}
	defer rows.Close()
	out := map[string]map[string]int64{}
	for rows.Next() {
		var kind, phase string
		var n int64
		if err := rows.Scan(&kind, &phase, &n); err != nil {
			return map[string]map[string]int64{}
		}
		ph := out[kind]
		if ph == nil {
			ph = map[string]int64{}
			out[kind] = ph
		}
		ph[phase] += n
	}
	return out
}

// ListAudit returns audit entries newest-first. The org filter is a
// prefix match on the logical key, mirroring the reference store.
func (s *Store) ListAudit(o state.AuditOptions) []state.AuditEntry {
	limit := o.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	where := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if o.Org != "" {
		args = append(args, escapeLike(o.Org)+"/%")
		where = append(where, fmt.Sprintf("logical_key LIKE $%d ESCAPE '\\'", len(args)))
	}
	if o.Kind != "" {
		args = append(args, o.Kind)
		where = append(where, fmt.Sprintf("kind = $%d", len(args)))
	}
	args = append(args, limit)
	query := `SELECT id, ts, actor, action, resource_id, kind, logical_key, generation, reason
                FROM audit WHERE ` + strings.Join(where, " AND ") +
		fmt.Sprintf(` ORDER BY seq DESC LIMIT $%d`, len(args))

	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]state.AuditEntry, 0, limit)
	for rows.Next() {
		var e state.AuditEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.Actor, &e.Action, &e.ResourceID,
			&e.Kind, &e.LogicalKey, &e.Generation, &e.Reason); err != nil {
			return nil
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	return out
}

// AppendAudit records a caller-built entry (e.g. webhook delivery
// outcomes), filling in ID and Time when empty. The completed entry is
// returned; database failures are swallowed to honour the reference
// signature (no error return).
func (s *Store) AppendAudit(e state.AuditEntry) state.AuditEntry {
	if e.ID == "" {
		e.ID = newAuditID()
	}
	if e.Time.IsZero() {
		e.Time = nowMicro()
	}
	ctx, cancel := s.ctx()
	defer cancel()
	if err := insertAudit(ctx, s.db, e); err != nil {
		return e
	}
	return e
}

// escapeLike neutralises LIKE metacharacters in a filter value so the
// org prefix match is literal.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// specLabelsEqual reports whether spec/labels actually changed
// (generation-relevant equality, identical to the reference store).
func specLabelsEqual(a, b *state.Resource) bool {
	eq := func(m1, m2 map[string]string) bool {
		if len(m1) != len(m2) {
			return false
		}
		for k, v := range m1 {
			if m2[k] != v {
				return false
			}
		}
		return true
	}
	if !eq(a.Labels, b.Labels) {
		return false
	}
	r1, _ := json.Marshal(a.Spec)
	r2, _ := json.Marshal(b.Spec)
	return string(r1) == string(r2)
}
