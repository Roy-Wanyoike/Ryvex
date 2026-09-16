package state

import "context"

// Backend is the storage contract every Ryvex state store must
// satisfy: the in-memory reference Store, and durable implementations
// such as the Postgres store in internal/state/pgstore. Consumers
// (API, reconciler, webhook dispatcher, seeder) depend on this
// interface so the backing store can be swapped at boot.
//
// Issue #71: the read paths that used to swallow errors (Count,
// CountByKindPhase, ListAudit, AppendAudit) now propagate them, and
// every backend answers Ping so /healthz and /readyz can report real
// dependency health.
type Backend interface {
	CreateResource(r *Resource, opts WriteOptions) (*Resource, error)
	GetResource(id string) (*Resource, error)
	GetByLogicalKey(org, project, env, kind, name string) (*Resource, error)
	ListResources(o ListOptions) ([]*Resource, string, error)
	UpdateResource(id string, fn func(*Resource) error, o UpdateOptions) (*Resource, error)
	UpdateStatus(id string, phase, message string, actor WriteOptions) error
	DeleteResource(id string, opts WriteOptions) error
	// Count returns the number of stored resources. Database errors
	// are propagated, not reported as an empty store (issue #71).
	Count() (int, error)
	// CountByKindPhase returns the per-kind/per-phase snapshot backing
	// the ryvex_resources metrics gauge.
	CountByKindPhase() (map[string]map[string]int64, error)
	// ListAudit returns audit entries newest-first.
	ListAudit(o AuditOptions) ([]AuditEntry, error)
	// AppendAudit records a caller-built audit entry and returns the
	// completed entry. Insert failures are propagated (issue #71) so a
	// lost compliance trail is never mistaken for success.
	AppendAudit(e AuditEntry) (AuditEntry, error)
	// Ping performs a cheap health check — on durable backends a real
	// database round trip. nil means the store can serve requests; it
	// backs /healthz and /readyz (issue #71).
	Ping(ctx context.Context) error
}
