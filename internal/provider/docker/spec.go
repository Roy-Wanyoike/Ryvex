// Package docker implements the reference provider.Actuator (issue
// #80): it drives Application resources against a Docker Engine over
// the engine's unix socket, using only stdlib (net/http +
// encoding/json). The actuator itself is behind the `docker` build
// tag; this file and client.go are tag-free so the pure logic — spec
// parsing, plan computation, field normalization, JSON decoding and
// error classification — is exercised by the default test gates
// without a docker daemon.
//
// Field vocabulary (drift comparison):
//
//	image:     required string, the container image reference
//	env.<KEY>: one field per env variable, value verbatim
//
// Expanding env to per-variable fields is what makes drift detection
// exact: the Engine merges image-defined variables (PATH and friends)
// into a container's Config.Env, and per-key fields let CompareFields
// ignore those undeclared extras while still catching a declared
// variable whose value moved or disappeared. The canonical "k=v,k=v"
// string form remains accepted as INPUT for convenience (values must
// not contain commas there); the normalized form is always per-key.
// The mapping is idempotent over its own output —
// DesiredFields(FieldsToSpec(DesiredFields(s))) == DesiredFields(s) —
// the property the reconciler's drift re-apply relies on.
package docker

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Normalized drift field names. Env variables live under the
// FieldEnvPrefix namespace ("env.A" for variable A), one field per
// variable.
const (
	FieldImage     = "image"
	FieldEnv       = "env"
	FieldEnvPrefix = FieldEnv + "."
)

// ContainerName derives the managed container's deterministic name
// from the resource's scope. Logical-key uniqueness (org/project/env/
// kind/name) guarantees a 1:1 mapping, and resource validation already
// constrains every segment to [a-z0-9-], which is a valid docker name
// charset. The prefix keeps managed containers greppable.
func ContainerName(ref provider.Ref) string {
	return "ryvex-" + ref.Org + "-" + ref.Project + "-" + ref.Env + "-" + ref.Name
}

// DesiredFields maps an Application spec to the normalized drift
// fields. spec.image is required. Env variables are accepted in three
// shapes and always expand to one field per variable:
//
//	env: {K: V, ...}      object with string values
//	env: ["K=V", ...]     list of key=value strings
//	env: "K=V,K=V"        packed canonical string (values must not
//	                     contain ',')
//	env.<K>: V            flat per-variable keys — exactly the shape
//	                     FieldsToSpec produces from observed state,
//	                     which makes the mapping round-trip
func DesiredFields(spec map[string]any) (map[string]string, error) {
	out := map[string]string{}
	img, _ := spec["image"].(string)
	img = strings.TrimSpace(img)
	if img == "" {
		return nil, errors.New("spec.image is required for actuated Application resources")
	}
	out[FieldImage] = img
	if raw, ok := spec[FieldEnv]; ok && raw != nil {
		pairs, err := envPairs(raw)
		if err != nil {
			return nil, fmt.Errorf("spec.env: %w", err)
		}
		for k, v := range pairs {
			out[FieldEnvPrefix+k] = v
		}
	}
	// Flat per-variable keys last, so the observed-state round-trip
	// form wins over an "env" block if a spec carries both.
	for k, v := range spec {
		key, ok := strings.CutPrefix(k, FieldEnvPrefix)
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("spec %q must be a string", k)
		}
		if key == "" {
			return nil, fmt.Errorf("spec key %q needs a variable name after the prefix", k)
		}
		out[k] = s
	}
	return out, nil
}

// envPairs flattens any accepted "env" representation into key/value
// pairs, rejecting malformed shapes: the spec is controller input and
// a silently-dropped variable would surface later as mystery drift.
// Order is not meaningful: fields are a map.
func envPairs(raw any) (map[string]string, error) {
	switch v := raw.(type) {
	case map[string]any:
		m := make(map[string]string, len(v))
		for k, val := range v {
			if k == "" {
				return nil, errors.New("env keys must not be empty")
			}
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("env %q must be a string", k)
			}
			m[k] = s
		}
		return m, nil
	case []any:
		m := make(map[string]string, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New(`env list entries must be "key=value" strings`)
			}
			k, val, ok := strings.Cut(s, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("env entry %q must be key=value", s)
			}
			m[k] = val
		}
		return m, nil
	case string:
		// Packed canonical form: values must not contain ',' (it is the
		// separator, and a value that swallowed the next pair is a lie
		// waiting to happen).
		m := make(map[string]string)
		for _, part := range strings.Split(v, ",") {
			if part == "" {
				continue
			}
			k, val, ok := strings.Cut(part, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("env entry %q must be key=value", part)
			}
			m[k] = val
		}
		return m, nil
	default:
		return nil, fmt.Errorf("env must be an object, a list of key=value strings, or a packed \"k=v,k=v\" string (got %T)", raw)
	}
}

// EnvListToFields maps an Engine-style env list (as returned by
// container inspect) into per-variable drift fields ("env.K": "v").
// Malformed entries are skipped: an engine-injected oddity is not
// drift.
func EnvListToFields(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		out[FieldEnvPrefix+k] = v
	}
	return out
}

// PlanContainers is the pure plan computation for one Application
// resource. current == nil (or an unusable current spec) yields a
// create plan carrying the full desired field set; otherwise the
// specs are diffed through DesiredFields into update/noop. Plan
// errors classify as Permanent: they are controller input errors and
// retrying them is lying.
func PlanContainers(current, desired *state.Resource) (provider.Plan, error) {
	want, err := DesiredFields(desired.Spec)
	if err != nil {
		return provider.Plan{}, provider.E(provider.Permanent, "plan", err)
	}
	plan := provider.Plan{Kind: desired.Kind, Action: provider.ActionCreate, Desired: desired}
	for _, k := range sortedFieldKeys(want) {
		plan.Changes = append(plan.Changes, provider.Change{Field: k, To: want[k]})
	}
	if current == nil {
		return plan, nil
	}
	have, herr := DesiredFields(current.Spec)
	if herr != nil {
		have = map[string]string{} // unreadable current: force a full update
	}
	drift := provider.CompareFields(want, have)
	if len(drift) == 0 {
		plan.Action = provider.ActionNoop
		plan.Changes = nil
		return plan, nil
	}
	plan.Action = provider.ActionUpdate
	plan.Changes = nil
	for _, k := range drift {
		plan.Changes = append(plan.Changes, provider.Change{Field: k, From: have[k], To: want[k]})
	}
	return plan, nil
}

func sortedFieldKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// classifyStatus maps a Docker Engine HTTP status code onto the SPI
// error taxonomy (docs/adr/0002-provider-spi.md): 5xx and throttles
// are Transient, deterministic 4xx rejections are Permanent. 404 is
// handled by callers as absence and never reaches this classifier.
func ClassifyStatus(code int) provider.Class {
	switch {
	case code == 429 || code == 409:
		return provider.Transient // throttles and create races resolve on retry
	case code >= 500:
		return provider.Transient
	case code >= 400:
		return provider.Permanent
	default:
		return provider.Transient
	}
}
