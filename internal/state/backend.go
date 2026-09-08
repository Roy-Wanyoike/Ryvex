package state

// Backend is the storage contract every Ryvex state store must
// satisfy: the in-memory reference Store, and durable implementations
// such as the Postgres store in internal/state/pgstore. Consumers
// (API, reconciler, webhook dispatcher, seeder) depend on this
// interface so the backing store can be swapped at boot.
type Backend interface {
	CreateResource(r *Resource, opts WriteOptions) (*Resource, error)
	GetResource(id string) (*Resource, error)
	GetByLogicalKey(org, project, env, kind, name string) (*Resource, error)
	ListResources(o ListOptions) ([]*Resource, string, error)
	UpdateResource(id string, fn func(*Resource) error, o UpdateOptions) (*Resource, error)
	UpdateStatus(id string, phase, message string, actor WriteOptions) error
	DeleteResource(id string, opts WriteOptions) error
	Count() int
	CountByKindPhase() map[string]map[string]int64
	ListAudit(o AuditOptions) []AuditEntry
	AppendAudit(e AuditEntry) AuditEntry
}
