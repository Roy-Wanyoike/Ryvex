package webhook

// Egress guard (issue #36): the dispatcher refuses to deliver webhooks
// to private, loopback, link-local or CGNAT targets.
//
// Defense in depth across the two halves of the lifetime of a
// Subscription URL:
//
//  1. Create/update time — state.ParseSubscriptionSpec validates the URL
//     and refuses forbidden targets with a *state.ValidationError
//     (HTTP 400 at the API).
//
//  2. Dispatch time (this file) — DNS can change between create and
//     deliver (DNS rebinding: validate a public name, rebind it to
//     169.254.169.254, wait for a retry). So every delivery attempt
//     re-resolves the target host and re-checks every returned address
//     with state.IsForbiddenWebhookIP BEFORE connecting. A refusal is
//     terminal: nothing is sent, nothing is retried, and the refusal is
//     appended to the audit log as "webhook_failed" with an "egress
//     blocked" reason.
//
// Redirects are denied outright by the delivery client (denyRedirect):
// a followed redirect would re-POST the signed body to a Location
// chosen by the first responder — an internal target the egress guard
// never re-checked — leaking the HMAC signature cross-host.
//
// Opt-out: on-prem deployments that legitimately deliver to internal
// targets set RYVEX_ALLOW_PRIVATE_WEBHOOKS=1 (see
// state.EnvAllowPrivateWebhooks). The dispatcher reads the environment
// at dispatch time unless Options.AllowPrivateEgress overrides it.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// egressResolveTimeout bounds the dispatch-time DNS re-resolution so a
// slow resolver cannot stall a worker for long.
const egressResolveTimeout = 3 * time.Second

// denyRedirect is the delivery client's CheckRedirect policy: every
// redirect is refused. See the package comment for why following (or
// even re-validating each hop) is not worth the risk in this build.
func denyRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("webhook: redirect to %q denied (egress policy: redirects are not followed)", req.URL)
}

// allowPrivateEgress resolves the private-target opt-in for this
// dispatcher. An explicit Options.AllowPrivateEgress wins; otherwise the
// documented RYVEX_ALLOW_PRIVATE_WEBHOOKS=1 environment opt-in is read
// at dispatch time, so operators can flip it without a rebuild.
func (d *Dispatcher) allowPrivateEgress() bool {
	if d.opts.AllowPrivateEgress != nil {
		return *d.opts.AllowPrivateEgress
	}
	return state.PrivateWebhookEgressAllowed()
}

// checkEgress re-validates the subscription's target URL immediately
// before a delivery attempt: the host must be a public IP literal, or a
// hostname whose current resolution contains no forbidden address.
// Returning a non-nil error means "do not connect".
func (d *Dispatcher) checkEgress(view *subView) error {
	if d.allowPrivateEgress() {
		return nil // documented on-prem opt-in
	}
	u, err := url.Parse(view.spec.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("target host is empty")
	}
	// A zone identifier ("fe80::1%eth0") only exists on link-scope
	// addresses; refuse without resolving.
	if strings.Contains(host, "%") {
		return fmt.Errorf("target %q is zone-scoped (link-local scope)", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := state.ForbiddenWebhookIPReason(ip); reason != "" {
			return fmt.Errorf("target %s is a %s", host, reason)
		}
		return nil
	}
	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, egressResolveTimeout)
	defer cancel()
	addrs, err := d.opts.Resolver.LookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve host %q: %w", host, err)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if reason := state.ForbiddenWebhookIPReason(ip); reason != "" {
			return fmt.Errorf("host %q re-resolves to a %s (%s)", host, reason, a)
		}
	}
	return nil
}
