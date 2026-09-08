package state

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
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

// EnvAllowPrivateWebhooks is the documented operator opt-in (issue #36)
// that permits Subscription webhook targets on private, loopback,
// link-local or CGNAT addresses for on-prem deployments:
//
//	RYVEX_ALLOW_PRIVATE_WEBHOOKS=1
//
// It is honored by spec validation (here) and read by the webhook
// dispatcher at dispatch time. Without it, any value other than "1"
// leaves the egress guard fully enabled.
const EnvAllowPrivateWebhooks = "RYVEX_ALLOW_PRIVATE_WEBHOOKS"

// egressResolveTimeout bounds the DNS lookup performed while validating
// a Subscription URL so spec validation stays fast and bounded.
const egressResolveTimeout = 3 * time.Second

// HostResolver resolves hostnames to addresses. It is satisfied by
// *net.Resolver (net.DefaultResolver) and by test doubles.
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// WebhookHostResolver resolves Subscription URL hostnames during spec
// validation (the DNS leg of the egress guard). Injectable for tests;
// defaults to net.DefaultResolver.
var WebhookHostResolver HostResolver = net.DefaultResolver

// PrivateWebhookEgressAllowed reports whether the documented
// RYVEX_ALLOW_PRIVATE_WEBHOOKS=1 opt-in is set. Shared by validation
// and the dispatcher so both sides agree on the escape hatch.
func PrivateWebhookEgressAllowed() bool {
	return os.Getenv(EnvAllowPrivateWebhooks) == "1"
}

// ForbiddenWebhookIPReason returns a human-readable reason when ip falls
// into an address range the webhook egress guard refuses to deliver to
// (issue #36), or "" when the address is an acceptable public target.
// Refused ranges: loopback, link-local, RFC1918 private (plus IPv6 ULA),
// CGNAT 100.64.0.0/10, unspecified/this-network, multicast and the
// reserved 240.0.0.0/4 block.
func ForbiddenWebhookIPReason(ip net.IP) string {
	if ip == nil {
		return "invalid address"
	}
	if v4 := ip.To4(); v4 != nil { // also matches IPv4-mapped IPv6
		switch {
		case v4[0] == 0:
			return "non-public address (0.0.0.0/8)"
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
			return "non-public address (CGNAT 100.64.0.0/10)"
		case v4[0] >= 240: // includes 255.255.255.255 broadcast
			return "non-public address (reserved 240.0.0.0/4)"
		}
	}
	switch {
	case ip.IsUnspecified():
		return "non-public address (unspecified)"
	case ip.IsLoopback():
		return "loopback address (127.0.0.0/8, ::1)"
	case ip.IsLinkLocalUnicast():
		return "link-local address (169.254.0.0/16, fe80::/10)"
	case ip.IsPrivate():
		return "private address (RFC1918 10/8, 172.16/12, 192.168/16; IPv6 ULA fc00::/7)"
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "multicast address"
	}
	return ""
}

// IsForbiddenWebhookIP reports whether ip is refused by the webhook
// egress guard; see ForbiddenWebhookIPReason for the refused ranges.
func IsForbiddenWebhookIP(ip net.IP) bool {
	return ForbiddenWebhookIPReason(ip) != ""
}

// reservedTLDHost reports whether host falls under an RFC 6761
// special-use TLD that can never resolve on the public internet
// (.test, .example, .invalid). Such names cannot address a routable
// target, so they carry no SSRF risk and skip the create-time DNS
// check; this also keeps the repository's example.test fixtures valid
// in offline test environments.
func reservedTLDHost(host string) bool {
	h := strings.ToLower(host)
	for _, tld := range []string{".test", ".example", ".invalid"} {
		if strings.HasSuffix(h, tld) {
			return true
		}
	}
	return false
}

// validateWebhookEgress enforces the webhook SSRF egress policy on a
// parsed Subscription URL (issue #36). Refused with a *ValidationError
// (HTTP 400 at the API) when the host is a forbidden IP literal, or a
// hostname that is unresolvable or resolves to a forbidden address.
// The RYVEX_ALLOW_PRIVATE_WEBHOOKS=1 opt-in bypasses the network checks
// for on-prem deployments that genuinely deliver internally.
func validateWebhookEgress(u *url.URL) error {
	if PrivateWebhookEgressAllowed() {
		return nil
	}
	host := u.Hostname()
	if host == "" { // e.g. "http://:8080/" parses with a non-empty Host
		return &ValidationError{Field: "spec", Message: "spec.url host is empty"}
	}
	// A zone identifier ("fe80::1%eth0") only exists on link-scope
	// addresses; refuse without resolving.
	if strings.Contains(host, "%") {
		return &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.url host %q is zone-scoped (link-local scope); such targets are refused", host)}
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := ForbiddenWebhookIPReason(ip); reason != "" {
			return &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.url host %q is a %s; private and internal targets are refused unless %s=1", host, reason, EnvAllowPrivateWebhooks)}
		}
		return nil
	}
	if reservedTLDHost(host) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), egressResolveTimeout)
	defer cancel()
	addrs, err := WebhookHostResolver.LookupHost(ctx, host)
	if err != nil {
		return &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.url host %q does not resolve; unresolvable webhook targets are refused (set %s=1 to bypass egress validation for on-prem use)", host, EnvAllowPrivateWebhooks)}
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if reason := ForbiddenWebhookIPReason(ip); reason != "" {
			return &ValidationError{Field: "spec", Message: fmt.Sprintf("spec.url host %q resolves to a %s (%s); private and internal targets are refused unless %s=1", host, reason, a, EnvAllowPrivateWebhooks)}
		}
	}
	return nil
}

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
	// Webhook SSRF egress guard (issue #36): refuse loopback,
	// link-local, RFC1918, CGNAT and unresolvable targets at
	// create/update time. The dispatcher re-checks the resolved IP
	// at dispatch time (DNS rebinding defense).
	if err := validateWebhookEgress(u); err != nil {
		return out, err
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
