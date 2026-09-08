package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// TestMain opts the webhook test binary into private-target delivery:
// every httptest server below lives on 127.0.0.1, which the SSRF egress
// guard (issue #36) refuses by default. This mirrors what an on-prem
// deployment sets; individual tests that exercise the guard override it
// with t.Setenv or Options.AllowPrivateEgress.
func TestMain(m *testing.M) {
	os.Setenv(state.EnvAllowPrivateWebhooks, "1")
	os.Exit(m.Run())
}

// ---- helpers ----

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testOptions builds deterministic Options: fast backoff, frozen clock,
// keep-alives disabled so no idle connection goroutines linger for the
// NumGoroutine sanity check.
func testOptions(serverSecret string, mutate func(*Options)) Options {
	o := Options{
		ServerSecret: serverSecret,
		Logger:       discardLogger(),
		Clock:        func() time.Time { return time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC) },
	}
	o.Client = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	if mutate != nil {
		mutate(&o)
	}
	return o
}

func createSubscription(t *testing.T, st *state.Store, org, name string, spec map[string]any) *state.Resource {
	t.Helper()
	r := &state.Resource{
		Kind: state.KindSubscription, Org: org, Project: "core", Env: "prod",
		Name: name, Spec: spec,
	}
	got, err := st.CreateResource(r, state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create Subscription %s: %v", name, err)
	}
	return got
}

func deleteSubscription(t *testing.T, st *state.Store, b *bus.Bus, id string) {
	t.Helper()
	res, err := st.GetResource(id)
	if err != nil {
		t.Fatalf("get subscription for delete: %v", err)
	}
	if err := st.DeleteResource(res.ID, state.WriteOptions{Actor: "test"}); err != nil {
		t.Fatalf("delete subscription: %v", err)
	}
	b.Publish(bus.Event{ // mirror what the API publishes on delete
		Type: bus.EventDeleted, Org: res.Org, Project: res.Project, Env: res.Env,
		Kind: res.Kind, Name: res.Name, ResourceID: res.ID, Actor: "test",
	})
}

func publishCreated(b *bus.Bus, org, name string) {
	b.Publish(bus.Event{
		Type: bus.EventCreated, Org: org, Project: "core", Env: "prod",
		Kind: "Application", Name: name, ResourceID: "r-" + name, Generation: 1,
		Actor: "test",
	})
}

type capture struct {
	body   []byte
	header http.Header
}

func captureServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, <-chan capture) {
	t.Helper()
	ch := make(chan capture, 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		ch <- capture{body: body, header: r.Header.Clone()}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func recv(t *testing.T, ch <-chan capture, timeout time.Duration) capture {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(timeout):
		t.Fatal("timed out waiting for webhook delivery")
		return capture{}
	}
}

func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// webhookAudit returns the dispatcher-written audit entries.
func webhookAudit(st *state.Store) []state.AuditEntry {
	entries := st.ListAudit(state.AuditOptions{Kind: state.KindSubscription, Limit: 500})
	var out []state.AuditEntry
	for _, e := range entries {
		if e.Actor == AuditActor {
			out = append(out, e)
		}
	}
	return out
}

func countActions(entries []state.AuditEntry, action string) int {
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// expectedSignature recomputes what the dispatcher must have sent:
// secret = hex(HMAC-SHA256(serverSecret, subID));
// sig = "sha256=" + hex(HMAC-SHA256(secret, rawBody)).
func expectedSignature(serverSecret, subID string, body []byte) (secretHex, sig string) {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(subID))
	secretHex = hex.EncodeToString(mac.Sum(nil))
	mac2 := hmac.New(sha256.New, []byte(secretHex))
	mac2.Write(body)
	return secretHex, "sha256=" + hex.EncodeToString(mac2.Sum(nil))
}

// ---- tests ----

func TestBusMatchMatrix(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		// exact
		{"ryvex.resource.acme.application.created", "ryvex.resource.acme.application.created", true},
		{"ryvex.resource.acme.application.created", "ryvex.resource.acme.application.updated", false},
		// > tail
		{"ryvex.resource.acme.>", "ryvex.resource.acme.application.created", true},
		{"ryvex.resource.acme.>", "ryvex.resource.acme.subscription.deleted", true},
		{"ryvex.resource.acme.>", "ryvex.resource.other.application.created", false},
		{"ryvex.resource.acme.>", "ryvex.resource.acme", false}, // > consumes at least one segment
		{">", "ryvex.resource.acme.application.created", true},
		// * single segment
		{"ryvex.resource.acme.*.created", "ryvex.resource.acme.application.created", true},
		{"ryvex.resource.acme.*.created", "ryvex.resource.acme.database.created", true},
		{"ryvex.resource.acme.*.created", "ryvex.resource.acme.application.updated", false},
		{"ryvex.resource.acme.*.created", "ryvex.resource.acme.a.b.created", false},
		{"*", "one", true},
		{"*", "one.two", false},
		// arity mismatches
		{"ryvex.resource.acme.application.created", "ryvex.resource.acme.application", false},
		{"ryvex.resource.acme.application", "ryvex.resource.acme.application.created", false},
		// non-match
		{"ryvex.resource.other.>", "ryvex.resource.acme.application.created", false},
	}
	for _, tc := range cases {
		if got := bus.Match(tc.pattern, tc.subject); got != tc.want {
			t.Errorf("bus.Match(%q, %q) = %v, want %v", tc.pattern, tc.subject, got, tc.want)
		}
	}
}

func TestDeliverySignedPayload(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	srv, deliveries := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	sub := createSubscription(t, st, "hooks", "main", map[string]any{
		"url":      srv.URL + "/hook",
		"subjects": []any{"ryvex.resource.acme.application.>"},
	})

	const serverSecret = "unit-test-server-secret"
	d := NewDispatcher(st, b, testOptions(serverSecret, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "checkout")
	got := recv(t, deliveries, 5*time.Second)

	if got.header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.header.Get("Content-Type"))
	}
	if id := got.header.Get("X-Ryvex-Subscription-ID"); id != sub.ID {
		t.Errorf("X-Ryvex-Subscription-ID = %q, want %q", id, sub.ID)
	}
	if got.header.Get("X-Ryvex-Event-ID") == "" {
		t.Error("X-Ryvex-Event-ID header missing")
	}
	_, wantSig := expectedSignature(serverSecret, sub.ID, got.body)
	if sig := got.header.Get("X-Ryvex-Signature"); sig != wantSig {
		t.Errorf("X-Ryvex-Signature = %q, want %q", sig, wantSig)
	}

	var payload map[string]any
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v (%s)", err, got.body)
	}
	wantFields := map[string]any{
		"subscription_id": sub.ID,
		"type":            "created",
		"subject":         "ryvex.resource.acme.application.created",
		"org":             "acme",
		"project":         "core",
		"env":             "prod",
		"kind":            "Application",
		"name":            "checkout",
		"resource_id":     "r-checkout",
	}
	for k, want := range wantFields {
		if got := payload[k]; got != want {
			t.Errorf("payload[%q] = %v, want %v", k, got, want)
		}
	}
	if payload["id"] == "" {
		t.Error("payload.id missing")
	}
	if _, ok := payload["time"]; !ok {
		t.Error("payload.time missing")
	}
}

func TestRetryThenSuccessAuditsAttempts(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	var calls atomic.Int32
	srv, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	createSubscription(t, st, "hooks", "retry", map[string]any{ // max_retries omitted -> 5
		"url":      srv.URL,
		"subjects": []any{"ryvex.resource.acme.application.>"},
	})

	d := NewDispatcher(st, b, testOptions("secret", nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "payments")
	waitUntil(t, "3 delivery attempts", 5*time.Second, func() bool { return calls.Load() == 3 })
	// Issue #65: the dispatcher writes the "delivered" audit entry after
	// the third response is classified, which can lag the call landing
	// at the mock server (deterministic failure under -race). Wait for
	// the audit trail itself instead of asserting it racing the write.
	waitUntil(t, "3 audit entries", 5*time.Second, func() bool { return len(webhookAudit(st)) == 3 })

	entries := webhookAudit(st)
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d, want 3 (failed, failed, delivered)", len(entries))
	}
	// ListAudit is newest-first: reverse into attempt order.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	wantOrder := []string{ActionFailed, ActionFailed, ActionDelivered}
	for i, e := range entries {
		if e.Action != wantOrder[i] {
			t.Errorf("audit[%d].action = %q, want %q", i, e.Action, wantOrder[i])
		}
		if !strings.Contains(e.Reason, fmt.Sprintf("attempt %d/6", i+1)) {
			t.Errorf("audit[%d].reason = %q, want attempt %d/6", i, e.Reason, i+1)
		}
		if !strings.Contains(e.Reason, "ryvex.resource.acme.application.created") {
			t.Errorf("audit[%d].reason = %q, want subject in reason", i, e.Reason)
		}
	}
	// The audit entry references the Subscription resource.
	if entries[0].Kind != state.KindSubscription {
		t.Errorf("audit kind = %q, want %q", entries[0].Kind, state.KindSubscription)
	}
}

func TestRetryExhaustedThenQueueKeepsFlowing(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	var fail atomic.Bool
	fail.Store(true)
	var calls atomic.Int32
	srv, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	createSubscription(t, st, "hooks", "doomed", map[string]any{
		"url":         srv.URL,
		"subjects":    []any{"ryvex.resource.acme.application.>"},
		"max_retries": 1, // 2 attempts per delivery, backoff base 1ms
	})

	d := NewDispatcher(st, b, testOptions("secret", nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	// Event A exhausts its attempts (all 500s).
	publishCreated(b, "acme", "first")
	waitUntil(t, "2 failed attempts", 5*time.Second, func() bool { return calls.Load() == 2 })

	// Server recovers; event B must still be delivered (queue flows).
	fail.Store(false)
	publishCreated(b, "acme", "second")
	waitUntil(t, "delivery of second event", 5*time.Second, func() bool {
		return calls.Load() == 3 && countActions(webhookAudit(st), ActionDelivered) == 1
	})

	entries := webhookAudit(st)
	if got := countActions(entries, ActionFailed); got != 2 {
		t.Errorf("webhook_failed entries = %d, want 2 (event A exhausted)", got)
	}
	if got := countActions(entries, ActionDelivered); got != 1 {
		t.Errorf("webhook_delivered entries = %d, want 1 (event B)", got)
	}
}

func TestInactiveAndDeletedSubscriptions(t *testing.T) {
	st := state.NewStore()
	b := bus.New()

	var activeCalls, inactiveCalls atomic.Int32
	srvActive, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		activeCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srvInactive, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		inactiveCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	subActive := createSubscription(t, st, "hooks", "on", map[string]any{
		"url":      srvActive.URL,
		"subjects": []any{"ryvex.resource.acme.application.>"},
	})
	createSubscription(t, st, "hooks", "off", map[string]any{
		"url":      srvInactive.URL,
		"subjects": []any{"ryvex.resource.acme.application.>"},
		"active":   false,
	})

	d := NewDispatcher(st, b, testOptions("secret", nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "one")
	waitUntil(t, "delivery to active subscription", 5*time.Second, func() bool { return activeCalls.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	if inactiveCalls.Load() != 0 {
		t.Errorf("inactive subscription received %d deliveries, want 0", inactiveCalls.Load())
	}

	// Deleting the active subscription stops further deliveries.
	deleteSubscription(t, st, b, subActive.ID)
	waitUntil(t, "subscription view refresh after delete", 5*time.Second, func() bool {
		d.mu.RLock()
		defer d.mu.RUnlock()
		_, ok := d.subs[subActive.ID]
		return !ok
	})

	publishCreated(b, "acme", "two")
	time.Sleep(150 * time.Millisecond)
	if activeCalls.Load() != 1 {
		t.Errorf("deleted subscription received deliveries (count=%d), want none after delete", activeCalls.Load())
	}
}

func TestQueueOverflowDropsAndAudits(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	release := make(chan struct{})
	var calls atomic.Int32
	srv, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release // block the single worker
		w.WriteHeader(http.StatusOK)
	})
	createSubscription(t, st, "hooks", "slow", map[string]any{
		"url":      srv.URL,
		"subjects": []any{"ryvex.resource.acme.application.>"},
	})

	d := NewDispatcher(st, b, testOptions("secret", func(o *Options) { o.QueueSize = 2 }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "e1") // worker takes it and blocks inside the handler

	waitUntil(t, "worker to pick up first delivery", 5*time.Second, func() bool { return calls.Load() == 1 })

	// 9 more events while the worker is blocked: 2 fit the queue, 7 drop.
	for i := 2; i <= 10; i++ {
		publishCreated(b, "acme", fmt.Sprintf("e%d", i))
	}
	entries := webhookAudit(st)
	drops := 0
	for _, e := range entries {
		if strings.Contains(e.Reason, "queue overflow") {
			drops++
		}
	}
	if drops != 7 {
		t.Errorf("overflow drop audit entries = %d, want 7", drops)
	}

	close(release)
	waitUntil(t, "queued deliveries to drain", 5*time.Second, func() bool { return calls.Load() == 3 })
	if got := countActions(webhookAudit(st), ActionDelivered); got != 3 {
		t.Errorf("delivered entries = %d, want 3 (1 in-flight + 2 queued)", got)
	}
}

func TestConcurrentFanoutNoLeak(t *testing.T) {
	st := state.NewStore()
	b := bus.New()

	var sub1Calls, sub2Calls atomic.Int32
	srv1, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		sub1Calls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srv2, _ := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		sub2Calls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	createSubscription(t, st, "hooks", "a", map[string]any{
		"url": srv1.URL, "subjects": []any{"ryvex.resource.acme.>"},
	})
	createSubscription(t, st, "hooks", "b", map[string]any{
		"url": srv2.URL, "subjects": []any{"ryvex.resource.acme.application.created"},
	})

	before := runtime.NumGoroutine()
	d := NewDispatcher(st, b, testOptions("secret", nil))
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)

	const events = 50
	var publishWG sync.WaitGroup
	for i := 0; i < events; i++ {
		publishWG.Add(1)
		go func(n int) { // concurrent publishes, like parallel API writers
			defer publishWG.Done()
			publishCreated(b, "acme", fmt.Sprintf("app-%d", n))
		}(i)
	}
	publishWG.Wait()

	waitUntil(t, "all fan-out deliveries", 10*time.Second, func() bool {
		return sub1Calls.Load() == events && sub2Calls.Load() == events
	})

	if drops := countActions(webhookAudit(st), ActionFailed); drops != 0 {
		t.Errorf("webhook_failed entries = %d, want 0 (no drops under load)", drops)
	}

	d.Stop(5 * time.Second)
	time.Sleep(100 * time.Millisecond) // let runtime reap finished goroutines
	after := runtime.NumGoroutine()
	if after > before+5 {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
	cancel()
}

// ---- SSRF egress guard (issue #36) ----

// resolverFunc adapts a function to the state.HostResolver seam.
type resolverFunc func(ctx context.Context, host string) ([]string, error)

func (f resolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

func boolPtr(b bool) *bool { return &b }

// swapValidationResolver replaces the state-side resolver used by
// ParseSubscriptionSpec and restores the original on cleanup.
func swapValidationResolver(t *testing.T, r state.HostResolver) {
	t.Helper()
	orig := state.WebhookHostResolver
	state.WebhookHostResolver = r
	t.Cleanup(func() { state.WebhookHostResolver = orig })
}

func TestWebhookEgressIPGuard(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.254", "::1",
		"169.254.169.254", "fe80::1", "fe80::",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.1.1",
		"100.64.0.1", "100.127.255.255", // CGNAT 100.64/10 bounds
		"0.0.0.0", "224.0.0.1", "ff02::1",
		"240.0.0.1", "255.255.255.255",
		"fd00::1", "fdff::", // IPv6 ULA fc00::/7
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped forbidden
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q does not parse", s)
		}
		if !state.IsForbiddenWebhookIP(ip) {
			t.Errorf("IsForbiddenWebhookIP(%s) = false, want true", s)
		}
		if state.ForbiddenWebhookIPReason(ip) == "" {
			t.Errorf("ForbiddenWebhookIPReason(%s) empty for a blocked address", s)
		}
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"100.63.255.255", "100.128.0.1", // just outside CGNAT
		"172.32.0.1", "172.15.255.255", // just outside 172.16/12
		"2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888",
		"::ffff:8.8.8.8", // IPv4-mapped public
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q does not parse", s)
		}
		if state.IsForbiddenWebhookIP(ip) {
			t.Errorf("IsForbiddenWebhookIP(%s) = true, want false", s)
		}
	}
}

// TestParseSubscriptionSpecEgressValidation drives the create/update-time
// URL guard through the exported parse path. The env opt-in is cleared
// (overriding TestMain) so the guard is fully active.
func TestParseSubscriptionSpecEgressValidation(t *testing.T) {
	t.Setenv(state.EnvAllowPrivateWebhooks, "")
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// forbidden IP literals
		{"loopback v4", "http://127.0.0.1:8080/hook", true},
		{"ipv6 loopback", "http://[::1]/hook", true},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"ipv6 link-local", "http://[fe80::1]/hook", true},
		{"rfc1918 10/8", "http://10.0.0.1/hook", true},
		{"rfc1918 172.16/12", "http://172.16.0.1/hook", true},
		{"rfc1918 192.168/16", "http://192.168.1.1/hook", true},
		{"cgnat 100.64/10", "http://100.64.0.1/hook", true},
		{"unspecified", "http://0.0.0.0/hook", true},
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]/hook", true},
		{"ipv4-mapped private", "http://[::ffff:10.0.0.1]/hook", true},
		{"multicast", "http://224.0.0.1/hook", true},
		{"zone-scoped", "http://[fe80::1%25eth0]/hook", true},
		{"userinfo hides private host", "http://user:pass@10.0.0.1/", true},
		{"port-only host", "http://:8080/hook", true},
		// allowed
		{"public v4 literal", "http://93.184.216.34/hook", false},
		{"public v6 literal", "http://[2001:4860:4860::8888]/hook", false},
		// RFC 6761 special-use TLD: can never resolve publicly, no DNS needed
		{"reserved tld", "https://example.test/hook", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := state.ParseSubscriptionSpec(subSpecURL(tc.url))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSubscriptionSpec(%q) accepted, want refusal", tc.url)
				}
				var ve *state.ValidationError
				if !errors.As(err, &ve) || !errors.Is(err, state.ErrValidation) {
					t.Fatalf("error %T (%v) is not a *state.ValidationError wrapping ErrValidation", err, err)
				}
				if ve.Field != "spec" || !strings.Contains(ve.Message, "spec.url") {
					t.Errorf("error = field %q message %q, want spec/spec.url in message", ve.Field, ve.Message)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSubscriptionSpec(%q) refused: %v", tc.url, err)
			}
		})
	}
}

// TestParseSubscriptionSpecEgressResolution covers the DNS leg of the
// create-time guard with an injected resolver (no real DNS in tests).
func TestParseSubscriptionSpecEgressResolution(t *testing.T) {
	t.Setenv(state.EnvAllowPrivateWebhooks, "")
	cases := []struct {
		name    string
		ips     []string
		resErr  error
		wantErr bool
		inMsg   string
	}{
		{name: "unresolvable refused", resErr: errors.New("nx"), wantErr: true, inMsg: "does not resolve"},
		{name: "resolves private refused", ips: []string{"10.0.0.1"}, wantErr: true, inMsg: "10.0.0.1"},
		{name: "resolves link-local refused", ips: []string{"169.254.169.254"}, wantErr: true, inMsg: "169.254.169.254"},
		{name: "resolves public allowed", ips: []string{"93.184.216.34"}},
		{name: "any private in set refused", ips: []string{"93.184.216.34", "192.168.1.1"}, wantErr: true, inMsg: "192.168.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapValidationResolver(t, resolverFunc(func(ctx context.Context, host string) ([]string, error) {
				return tc.ips, tc.resErr
			}))
			_, err := state.ParseSubscriptionSpec(subSpecURL("https://hooks.example.com/endpoint"))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected refusal, got none")
				}
				if !strings.Contains(err.Error(), tc.inMsg) {
					t.Errorf("error %q does not mention %q", err.Error(), tc.inMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected acceptance, got: %v", err)
			}
		})
	}
}

// TestParseSubscriptionSpecEgressOptIn: RYVEX_ALLOW_PRIVATE_WEBHOOKS=1
// (the documented on-prem opt-in) lets private targets through validation.
func TestParseSubscriptionSpecEgressOptIn(t *testing.T) {
	t.Setenv(state.EnvAllowPrivateWebhooks, "1")
	for _, url := range []string{
		"http://127.0.0.1:9090/hook",
		"http://169.254.169.254/",
		"http://10.1.2.3/hook",
		"https://[fe80::1]/hook",
	} {
		got, err := state.ParseSubscriptionSpec(subSpecURL(url))
		if err != nil {
			t.Errorf("opt-in parse %q: %v", url, err)
			continue
		}
		if got.URL != url {
			t.Errorf("opt-in parse %q: URL = %q", url, got.URL)
		}
	}
}

// subSpecURL builds a minimal valid Subscription spec around url.
func subSpecURL(url string) map[string]any {
	return map[string]any{
		"url":      url,
		"subjects": []any{"ryvex.resource.acme.>"},
	}
}

// TestDispatchBlocksForbiddenTarget: a subscription whose URL is a
// loopback IP literal passes create-time validation (env opt-in active in
// this binary) but the dispatcher re-checks at dispatch time and refuses
// terminally: nothing is sent, nothing is retried, and the refusal lands
// in the audit log.
func TestDispatchBlocksForbiddenTarget(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	srv, deliveries := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	createSubscription(t, st, "hooks", "private", map[string]any{
		"url":         srv.URL, // http://127.0.0.1:<port> — forbidden literal
		"subjects":    []any{"ryvex.resource.acme.application.>"},
		"max_retries": 3, // would produce 3 more attempts if the guard retried
	})

	d := NewDispatcher(st, b, testOptions("secret", func(o *Options) {
		o.AllowPrivateEgress = boolPtr(false) // force the guard on despite TestMain opt-in
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "sensitive")
	waitUntil(t, "egress refusal audit entry", 5*time.Second, func() bool {
		for _, e := range webhookAudit(st) {
			if strings.Contains(e.Reason, "egress blocked") {
				return true
			}
		}
		return false
	})
	time.Sleep(150 * time.Millisecond) // grace: nothing may be sent afterwards
	select {
	case c := <-deliveries:
		t.Fatalf("forbidden target received a delivery: %s", c.body)
	default:
	}

	entries := webhookAudit(st)
	if got := countActions(entries, ActionFailed); got != 1 {
		t.Errorf("webhook_failed entries = %d, want 1 (terminal refusal, no retries)", got)
	}
	if got := countActions(entries, ActionDelivered); got != 0 {
		t.Errorf("webhook_delivered entries = %d, want 0", got)
	}
	for _, e := range entries {
		if !strings.Contains(e.Reason, "127.0.0.1") {
			t.Errorf("refusal reason %q does not name the offending address", e.Reason)
		}
	}
}

// TestDispatchRevalidationBlocksDNSRebinding: the subscription hostname
// is public when validated at create time, but by dispatch time it
// re-resolves to a private address (the rebinding attack). The dispatcher
// must refuse before connecting and audit the refusal.
func TestDispatchRevalidationBlocksDNSRebinding(t *testing.T) {
	st := state.NewStore()
	b := bus.New()

	// Validation-time view of DNS: the name is public.
	swapValidationResolver(t, resolverFunc(func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}))
	createSubscription(t, st, "hooks", "rebind", map[string]any{
		// Not under a reserved TLD, so create-time validation resolves it.
		"url":         "http://hooks.rebind.example.com/hook",
		"subjects":    []any{"ryvex.resource.acme.application.>"},
		"max_retries": 3,
	})

	// Dispatch-time view of DNS: the name has rebound to a private IP.
	d := NewDispatcher(st, b, testOptions("secret", func(o *Options) {
		o.AllowPrivateEgress = boolPtr(false)
		o.Resolver = resolverFunc(func(ctx context.Context, host string) ([]string, error) {
			return []string{"10.0.0.1"}, nil
		})
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "rebind")
	waitUntil(t, "rebinding refusal audit entry", 5*time.Second, func() bool {
		for _, e := range webhookAudit(st) {
			if strings.Contains(e.Reason, "egress blocked") && strings.Contains(e.Reason, "10.0.0.1") {
				return true
			}
		}
		return false
	})

	entries := webhookAudit(st)
	if got := countActions(entries, ActionFailed); got != 1 {
		t.Errorf("webhook_failed entries = %d, want 1 (terminal refusal, no retries)", got)
	}
	if got := countActions(entries, ActionDelivered); got != 0 {
		t.Errorf("webhook_delivered entries = %d, want 0", got)
	}
}

// TestDispatchDeniesRedirects: the delivery client must never follow a
// redirect — the signature header would be re-sent to the Location host.
func TestDispatchDeniesRedirects(t *testing.T) {
	st := state.NewStore()
	b := bus.New()
	srvB, hitsB := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // must never be reached
	})
	srvA, hitsA := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/landed", http.StatusFound)
	})
	createSubscription(t, st, "hooks", "redirector", map[string]any{
		"url":         srvA.URL,
		"subjects":    []any{"ryvex.resource.acme.application.>"},
		"max_retries": 0,
	})

	d := NewDispatcher(st, b, testOptions("secret", nil)) // default client gets the deny-redirect policy
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop(2 * time.Second)

	publishCreated(b, "acme", "redir")
	got := recv(t, hitsA, 5*time.Second)
	if got.header.Get("X-Ryvex-Signature") == "" {
		t.Error("X-Ryvex-Signature missing on the original request")
	}
	waitUntil(t, "failed attempt audit after redirect denial", 5*time.Second, func() bool {
		return countActions(webhookAudit(st), ActionFailed) == 1
	})
	time.Sleep(150 * time.Millisecond) // grace: the redirect target must stay silent
	select {
	case c := <-hitsB:
		t.Fatalf("redirect target received a request (signature leaked: %q)", c.header.Get("X-Ryvex-Signature"))
	default:
	}
	entries := webhookAudit(st)
	if got := countActions(entries, ActionDelivered); got != 0 {
		t.Errorf("webhook_delivered entries = %d, want 0", got)
	}
	if got := countActions(entries, ActionFailed); got != 1 {
		t.Errorf("webhook_failed entries = %d, want 1 (single denied attempt)", got)
	}
}
