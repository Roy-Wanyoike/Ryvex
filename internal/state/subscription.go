package state

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SubscriptionSpec is the decoded spec of a Subscription resource:
// a webhook endpoint plus the bus subject patterns it wants delivered.
//
//	{
//	  "url": "https://example.test/hook",
//	  "subjects": ["ryvex.resource.acme.>",
//	               "ryvex.resource.acme.deployment.created"],
//	  "active": true,
//	  "max_retries": 5
//	}
type SubscriptionSpec struct {
	URL        string   `json:"url"`
	Subjects   []string `json:"subjects"`
	Active     bool     `json:"active"`
	MaxRetries int      `json:"max_retries"`
}

// Subscription spec budgets.
const (
	MaxSubscriptionSubjects = 16 // subjects per subscription
	MaxSubscriptionRetries  = 10 // max_retries upper bound
	DefSubscriptionRetries  = 5  // max_retries default
)

// subjectSegRe is the allowed charset for one dot-separated subject
// segment: [A-Za-z0-9*>,.-] (wildcards * and >, literal . , -).
var subjectSegRe = regexp.MustCompile(`^[A-Za-z0-9*>,.-]+$`)

// ParseSubscriptionSpec decodes and validates the spec map of a
// Subscription resource. Defaults: active=true, max_retries=5. It
// returns a *ValidationError naming the offending field on failure.
func ParseSubscriptionSpec(spec map[string]any) (SubscriptionSpec, error) {
	out := SubscriptionSpec{Active: true, MaxRetries: DefSubscriptionRetries}
	if spec == nil {
		return out, &ValidationError{Field: "spec", Message: "spec is required"}
	}

	rawURL, ok := spec["url"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.url is required"}
	}
	rawURLStr, ok := rawURL.(string)
	if !ok || strings.TrimSpace(rawURLStr) == "" {
		return out, &ValidationError{Field: "spec", Message: "spec.url must be a non-empty string"}
	}
	u, err := url.Parse(rawURLStr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.url %q must be a valid http(s) URL", rawURLStr)}
	}
	out.URL = rawURLStr

	rawSubjects, ok := spec["subjects"]
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.subjects is required"}
	}
	arr, ok := rawSubjects.([]any)
	if !ok {
		return out, &ValidationError{Field: "spec", Message: "spec.subjects must be an array of subject patterns"}
	}
	if len(arr) == 0 {
		return out, &ValidationError{Field: "spec", Message: "spec.subjects must contain at least one subject pattern"}
	}
	if len(arr) > MaxSubscriptionSubjects {
		return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.subjects exceeds %d entries", MaxSubscriptionSubjects)}
	}
	out.Subjects = make([]string, 0, len(arr))
	for i, s := range arr {
		pattern, ok := s.(string)
		if !ok || !ValidBusPattern(pattern) {
			return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.subjects[%d] %q is not a valid bus subject pattern", i, s)}
		}
		out.Subjects = append(out.Subjects, pattern)
	}

	if v, ok := spec["active"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return out, &ValidationError{Field: "spec", Message: "spec.active must be a boolean"}
		}
		out.Active = b
	}

	if v, ok := spec["max_retries"]; ok && v != nil {
		n, ok := numericInt(v)
		if !ok {
			return out, &ValidationError{Field: "spec", Message: "spec.max_retries must be an integer"}
		}
		if n < 0 || n > MaxSubscriptionRetries {
			return out, &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.max_retries must be between 0 and %d", MaxSubscriptionRetries)}
		}
		out.MaxRetries = n
	}

	return out, nil
}

// ValidBusPattern reports whether p is a valid dot-separated bus
// subject pattern: non-empty segments over [A-Za-z0-9*>,.-], with ">"
// allowed only as the final segment (NATS-style tail wildcard).
func ValidBusPattern(p string) bool {
	if p == "" {
		return false
	}
	segs := strings.Split(p, ".")
	for i, seg := range segs {
		if !subjectSegRe.MatchString(seg) {
			return false
		}
		if seg == ">" && i != len(segs)-1 {
			return false
		}
	}
	return true
}

// numericInt accepts the JSON-decoded representations of an integer
// (float64 from encoding/json, or int from programmatic callers).
func numericInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}
