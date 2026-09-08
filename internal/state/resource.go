package state

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kinds registered in the control plane. The set is intentionally
// small and closed: it models the primitive building blocks of the
// Ryvex platform. New kinds must be added here and in Kinds below.
const (
	KindProject      = "Project"
	KindEnvironment  = "Environment"
	KindApplication  = "Application"
	KindDeployment   = "Deployment"
	KindCluster      = "Cluster"
	KindNode         = "Node"
	KindDatabase     = "Database"
	KindCache        = "Cache"
	KindBucket       = "Bucket"
	KindPolicy       = "Policy"
	KindSecret       = "Secret"
	KindSubscription = "Subscription"
)

// Kinds is the authoritative set of supported resource kinds.
var Kinds = map[string]bool{
	KindProject: true, KindEnvironment: true, KindApplication: true,
	KindDeployment: true, KindCluster: true, KindNode: true,
	KindDatabase: true, KindCache: true, KindBucket: true,
	KindPolicy: true, KindSecret: true, KindSubscription: true,
}

// Phases of the reconciliation lifecycle.
const (
	PhasePending      = "Pending"
	PhaseProvisioning = "Provisioning"
	PhaseReady        = "Ready"
	PhaseDegraded     = "Degraded"
	PhaseFailed       = "Failed"
	PhaseTerminating  = "Terminating"
)

// Resource is the central declarative object managed by Ryvex.
// It follows the familiar spec/status split: users declare Spec,
// the reconciler owns Status.
type Resource struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Org        string            `json:"org"`
	Project    string            `json:"project"`
	Env        string            `json:"env"`
	Name       string            `json:"name"`
	Generation int64             `json:"generation"`
	Labels     map[string]string `json:"labels,omitempty"`
	Spec       map[string]any    `json:"spec,omitempty"`
	Status     Status            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Status is the observed state, owned exclusively by the reconciler.
type Status struct {
	Phase          string    `json:"phase"`
	Message        string    `json:"message,omitempty"`
	ObservedGen    int64     `json:"observed_generation"`
	ConditionsJSON string    `json:"-"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// DeepCopy returns a defensive copy of the resource. Both Labels and
// Spec are deep-copied into FRESH maps: `cp := *r` only copies the map
// headers, so writing through cp.Spec would alias — and mutate — the
// stored resource's map (issue #28: data race + in-place corruption
// found by the race detector via json.Unmarshal reusing the aliased
// map).
func (r *Resource) DeepCopy() *Resource {
	cp := *r
	if r.Labels != nil {
		cp.Labels = make(map[string]string, len(r.Labels))
		for k, v := range r.Labels {
			cp.Labels[k] = v
		}
	}
	if r.Spec != nil {
		raw, _ := json.Marshal(r.Spec) // reads r.Spec: callers hold the store lock
		cp.Spec = make(map[string]any, len(r.Spec))
		_ = json.Unmarshal(raw, &cp.Spec)
	}
	return &cp
}

// LogicalKey is the unique human address of a resource inside its scope.
func (r *Resource) LogicalKey() string {
	return strings.Join([]string{r.Org, r.Project, r.Env, r.Kind, r.Name}, "/")
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	scopeRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	maxSpecB = 64 << 10 // 64 KiB spec budget per resource
)

// Validate enforces the resource schema. It returns a
// *ValidationError wrapping ErrValidation on the first failure.
func (r *Resource) Validate() error {
	if !Kinds[r.Kind] {
		return &ValidationError{Field: "kind", Message: fmt.Sprintf("unsupported kind %q; supported: %v", r.Kind, knownKinds())}
	}
	for _, f := range []struct{ name, v string }{{"org", r.Org}, {"project", r.Project}, {"env", r.Env}, {"name", r.Name}} {
		if !scopeRe.MatchString(f.v) {
			return &ValidationError{Field: f.name, Message: "must be 1-63 lowercase alphanumeric or '-', start/end alphanumeric"}
		}
	}
	for k, v := range r.Labels {
		if !labelRe.MatchString(k) {
			return &ValidationError{Field: "labels", Message: fmt.Sprintf("label key %q must be 1-63 alphanumeric/._- characters", k)}
		}
		if len(v) > 63 || !labelRe.MatchString(v) {
			return &ValidationError{Field: "labels", Message: fmt.Sprintf("label value %q must be 1-63 alphanumeric/._- characters", v)}
		}
	}
	if r.Spec == nil {
		return &ValidationError{Field: "spec", Message: "spec is required"}
	}
	raw, err := json.Marshal(r.Spec)
	if err != nil {
		return &ValidationError{Field: "spec", Message: "spec must be a JSON object"}
	}
	if len(raw) > maxSpecB {
		return &ValidationError{Field: "spec", Message: fmt.Sprintf("spec exceeds %d bytes", maxSpecB)}
	}
	// Kind-specific spec schemas.
	if r.Kind == KindSubscription {
		if _, err := ParseSubscriptionSpec(r.Spec); err != nil {
			return err
		}
	}
	return nil
}

func knownKinds() []string {
	out := make([]string, 0, len(Kinds))
	for k := range Kinds {
		out = append(out, k)
	}
	// deterministic order for error messages
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// AuditEntry records a single state mutation for the audit trail.
type AuditEntry struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"` // created | updated | deleted | status_changed
	ResourceID string    `json:"resource_id"`
	Kind       string    `json:"kind"`
	LogicalKey string    `json:"logical_key"`
	Generation int64     `json:"generation"`
	Reason     string    `json:"reason,omitempty"`
}
