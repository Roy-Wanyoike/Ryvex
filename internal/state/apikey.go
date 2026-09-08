package state

import (
	"fmt"
	"regexp"
	"strings"
)

// Reserved namespace coordinates: every managed API key is stored at
// org=ryvex / project=system / env=system. The org "ryvex" is rejected
// for every other kind (see Validate), so user state can never collide
// with the key namespace.
const (
	ReservedOrg     = "ryvex"
	ReservedProject = "system"
	ReservedEnv     = "system"
)

// RBAC roles a key may hold (issue #16).
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// Roles is the closed set of roles a managed key can carry.
var Roles = map[string]bool{
	RoleAdmin: true, RoleOperator: true, RoleViewer: true,
}

// MaxAPIKeyScopes bounds the scopes array per key.
const MaxAPIKeyScopes = 32

// wildcardScope is the placeholder scope for admin bootstrap keys;
// admin authorization ignores scopes entirely.
const wildcardScope = "org/*"

// APIKeySpec is the decoded spec of an APIKey resource:
//
//	{
//	  "principal": "ci-bot",
//	  "roles": ["operator"],
//	  "key_hash": "sha256hex",   // sha256(token), 64 lowercase hex
//	  "scopes": ["org/acme", "org/acme/project/core"],
//	  "active": true
//	}
type APIKeySpec struct {
	Principal string   `json:"principal"`
	Roles     []string `json:"roles"`
	KeyHash   string   `json:"key_hash"`
	Scopes    []string `json:"scopes"`
	Active    bool     `json:"active"`
}

var keyHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseAPIKeySpec decodes and validates the spec map of an APIKey
// resource. Defaults: active=true. It returns a *ValidationError
// naming the offending field on failure.
func ParseAPIKeySpec(spec map[string]any) (APIKeySpec, error) {
	out := APIKeySpec{Active: true}
	if spec == nil {
		return out, &ValidationError{Field: "spec", Message: "spec is required"}
	}

	rawPrincipal, ok := spec["principal"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.principal is required"}
	}
	principal, ok := rawPrincipal.(string)
	if !ok || !scopeRe.MatchString(principal) {
		return out, &ValidationError{Field: "spec", Message: "spec.principal must be 1-63 lowercase alphanumeric or '-' (DNS-1123)"}
	}
	out.Principal = principal

	rawRoles, ok := spec["roles"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.roles is required"}
	}
	roles, err := decodeStringSlice(rawRoles, "spec.roles")
	if err != nil {
		return out, err
	}
	if len(roles) == 0 {
		return out, &ValidationError{Field: "spec", Message: "spec.roles must contain at least one role"}
	}
	for i, role := range roles {
		if !Roles[role] {
			return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.roles[%d] %q must be one of: admin, operator, viewer", i, role)}
		}
	}
	out.Roles = roles

	rawHash, ok := spec["key_hash"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.key_hash is required"}
	}
	hash, ok := rawHash.(string)
	if !ok || !keyHashRe.MatchString(hash) {
		return out, &ValidationError{Field: "spec", Message: "spec.key_hash must be a 64-character lowercase hex sha256 digest"}
	}
	out.KeyHash = hash

	rawScopes, ok := spec["scopes"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.scopes is required"}
	}
	scopes, err := decodeStringSlice(rawScopes, "spec.scopes")
	if err != nil {
		return out, err
	}
	if len(scopes) > MaxAPIKeyScopes {
		return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.scopes exceeds %d entries", MaxAPIKeyScopes)}
	}
	admin := hasRole(roles, RoleAdmin)
	for i, scope := range scopes {
		if !ValidScope(scope, admin) {
			return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.scopes[%d] %q must be \"org/<org>\" or \"org/<org>/project/<project>\" with DNS-1123 segments", i, scope)}
		}
	}
	if len(scopes) == 0 && !admin {
		return out, &ValidationError{Field: "spec", Message: "spec.scopes must be non-empty for operator/viewer keys"}
	}
	out.Scopes = scopes

	if v, ok := spec["active"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return out, &ValidationError{Field: "spec", Message: "spec.active must be a boolean"}
		}
		out.Active = b
	}

	return out, nil
}

// ValidScope reports whether s is "org/<org>" or
// "org/<org>/project/<project>" with DNS-1123 segments. The wildcard
// "org/*" is valid only on admin keys (admin authorization ignores
// scopes entirely).
func ValidScope(s string, admin bool) bool {
	if s == wildcardScope {
		return admin
	}
	rest, ok := strings.CutPrefix(s, "org/")
	if !ok {
		return false
	}
	if org, project, found := strings.Cut(rest, "/project/"); found {
		return scopeRe.MatchString(org) && scopeRe.MatchString(project)
	}
	return scopeRe.MatchString(rest)
}

// NewAPIKeyResource builds a managed-key resource at the reserved
// address org=ryvex / project=system / env=system with name=principal.
func NewAPIKeyResource(principal string, roles, scopes []string, keyHash string) *Resource {
	return &Resource{
		Kind: KindAPIKey, Org: ReservedOrg, Project: ReservedProject, Env: ReservedEnv,
		Name: principal,
		Spec: map[string]any{
			"principal": principal,
			"roles":     anySlice(roles),
			"key_hash":  keyHash,
			"scopes":    anySlice(scopes),
			"active":    true,
		},
	}
}

// validateAPIKey enforces the APIKey schema: the reserved namespace,
// a DNS-1123 name matching spec.principal, and a valid key spec.
func (r *Resource) validateAPIKey() error {
	if r.Org != ReservedOrg {
		return &ValidationError{Field: "org", Message: fmt.Sprintf("managed API keys must use the reserved org %q", ReservedOrg)}
	}
	if r.Project != ReservedProject || r.Env != ReservedEnv {
		return &ValidationError{Field: "project", Message: fmt.Sprintf("managed API keys live only at %s/%s/%s", ReservedOrg, ReservedProject, ReservedEnv)}
	}
	if !scopeRe.MatchString(r.Name) {
		return &ValidationError{Field: "name", Message: "must be 1-63 lowercase alphanumeric or '-', start/end alphanumeric"}
	}
	spec, err := ParseAPIKeySpec(r.Spec)
	if err != nil {
		return err
	}
	if spec.Principal != r.Name {
		return &ValidationError{Field: "name", Message: fmt.Sprintf("resource name %q must match spec.principal %q", r.Name, spec.Principal)}
	}
	return nil
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// decodeStringSlice accepts the JSON-decoded ([]any) and programmatic
// ([]string) representations of a string array.
func decodeStringSlice(v any, field string) ([]string, error) {
	fail := func(msg string) ([]string, error) {
		return nil, &ValidationError{Field: field, Message: msg}
	}
	switch arr := v.(type) {
	case []any:
		out := make([]string, 0, len(arr))
		for i, item := range arr {
			s, ok := item.(string)
			if !ok {
				return fail(fmt.Sprintf("%s[%d] must be a string", field, i))
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return append([]string(nil), arr...), nil
	default:
		return fail(field + " must be an array of strings")
	}
}

func anySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
