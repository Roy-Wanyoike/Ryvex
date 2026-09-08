// Package webhook delivers bus events durably to Subscription
// resources over signed HTTP callbacks.
//
// A Subscription is a normal declarative resource (kind
// "Subscription", CRUD'd through the existing /v1 resources
// endpoints) whose spec declares a target URL, the bus subject
// patterns it cares about, and the retry policy:
//
//	{
//	  "url": "https://example.test/hook",
//	  "subjects": ["ryvex.resource.acme.>",
//	               "ryvex.resource.acme.deployment.created"],
//	  "active": true,
//	  "max_retries": 5
//	}
//
// The Dispatcher subscribes ONCE to the bus with "ryvex.resource.>"
// and matches every event against each Subscription's spec.subjects
// using the exact bus wildcard grammar (bus.Match). Matching events
// are enqueued on a bounded per-subscription queue and POSTed as a
// JSON envelope:
//
//	POST {url}
//	Content-Type: application/json
//	X-Ryvex-Signature: sha256=<hex hmac-sha256 of raw body>
//	X-Ryvex-Event-ID: <event id>
//	X-Ryvex-Subscription-ID: <subscription id>
//
//	{"id","time","type","subject","org","project","env","kind",
//	 "name","resource_id","generation","phase","actor","data",
//	 "subscription_id"}
//
// Per-subscription signing secrets are derived deterministically:
//
//	secret    = hex(HMAC-SHA256(server_secret, subscription_id))
//	signature = "sha256=" + hex(HMAC-SHA256(secret, raw_body))
//
// Receivers verify by recomputing the HMAC over the raw request body
// with the secret they were provisioned out of band.
//
// Failed attempts retry with exponential backoff (BackoffBase, 2x,
// 4x, ... — 1s/2s/4s in production) up to max_retries total attempts;
// success is any 2xx within RequestTimeout (5s default). Every
// attempt outcome is appended to the audit log (actions
// "webhook_delivered" / "webhook_failed", actor
// "webhook-dispatcher"). Overflowing a subscription queue drops the
// event and audits it instead of blocking the control plane.
//
// In this build the server secret is ephemeral (a flag/env value or
// random material generated at boot), so signatures rotate on
// restart; durable per-subscription secrets arrive with the secrets
// feature.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Defaults and constants for the dispatcher.
const (
	// SubjectPattern is the bus pattern the dispatcher subscribes with.
	SubjectPattern = bus.SubjectNamespace + ".>"

	// DefaultQueueSize bounds the pending deliveries per subscription.
	DefaultQueueSize = 256

	// DefaultRequestTimeout bounds a single delivery attempt.
	DefaultRequestTimeout = 5 * time.Second

	// DefaultBackoffBase is the first retry wait; it doubles per attempt.
	DefaultBackoffBase = time.Second

	// MaxBackoff caps the exponential growth of a single wait.
	MaxBackoff = time.Minute

	// AuditActor attributes audit entries written by the dispatcher.
	AuditActor = "webhook-dispatcher"

	// Audit actions appended per delivery attempt.
	ActionDelivered = "webhook_delivered"
	ActionFailed    = "webhook_failed"
)

// Options configures the Dispatcher. Every field is optional; zero
// values select production defaults.
type Options struct {
	// Client performs delivery POSTs. Per-attempt timeouts are
	// enforced via the request context, so a plain client is fine.
	Client *http.Client

	// Logger receives dispatcher logs (defaults to slog.Default()).
	Logger *slog.Logger

	// Clock sources timestamps for audit entries (test seam).
	Clock func() time.Time

	// BackoffBase is the first retry wait (default 1s), doubling
	// per subsequent attempt up to MaxBackoff.
	BackoffBase time.Duration

	// ServerSecret is the HMAC key material from which
	// per-subscription signing secrets are derived. When empty a
	// random secret is generated at construction time.
	ServerSecret string

	// RequestTimeout bounds one delivery attempt (default 5s).
	RequestTimeout time.Duration

	// QueueSize bounds each subscription's pending deliveries
	// (default 256). Overflowing events are dropped and audited.
	QueueSize int
}

// Dispatcher fans bus events out to Subscription resources. Construct
// with NewDispatcher, then Start(ctx) and Stop(timeout) like the
// reconciler. Safe for concurrent use.
type Dispatcher struct {
	store state.Backend
	bus   bus.BusI
	opts  Options
	log   *slog.Logger

	mu   sync.RWMutex
	subs map[string]*subHandle

	busSub   bus.Sub
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// subView is the immutable snapshot of a Subscription used by workers
// and the fan-out path; swapped atomically on resource updates.
type subView struct {
	res    *state.Resource
	spec   state.SubscriptionSpec
	secret string // hex(HMAC-SHA256(serverSecret, subID)) — shared with the receiver
}

// subHandle couples a subscription's view with its delivery queue and
// worker lifetime.
type subHandle struct {
	id    string
	view  atomic.Pointer[subView]
	queue chan delivery
	quit  chan struct{} // closed when the subscription is removed
}

// delivery is one pending webhook POST.
type delivery struct {
	event bus.Event
}

// deliveryPayload is the wire shape of a webhook: the full bus event
// plus the subscription that matched it.
type deliveryPayload struct {
	bus.Event
	SubscriptionID string `json:"subscription_id"`
}

// NewDispatcher constructs a dispatcher over the store and bus. Call
// Start to begin delivering. The store is state.Backend (issue #14);
// the bus is bus.BusI so the JetStream backend (issue #15) can drive
// webhooks too.
func NewDispatcher(store state.Backend, b bus.BusI, opts Options) *Dispatcher {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Client == nil {
		opts.Client = &http.Client{} // per-attempt timeout enforced via request context
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = DefaultBackoffBase
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = DefaultRequestTimeout
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}
	if opts.ServerSecret == "" {
		opts.ServerSecret = RandomSecret()
		opts.Logger.Info("webhook server secret generated at boot; set --webhook-secret for signatures stable across restarts")
	}
	return &Dispatcher{
		store: store,
		bus:   b,
		opts:  opts,
		log:   opts.Logger.With("component", "webhook-dispatcher"),
		subs:  map[string]*subHandle{},
	}
}

// RandomSecret returns 32 bytes of cryptographic randomness, hex
// encoded, for use as Options.ServerSecret.
func RandomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the platform entropy source is
		// broken; a deterministic fallback beats panicking at boot.
		return hex.EncodeToString([]byte("ryvex-insecure-fallback-webhook-secret"))
	}
	return hex.EncodeToString(b[:])
}

// Start loads the subscription view, launches one worker per
// subscription and subscribes to the bus. It returns immediately.
// Cancel ctx (or call Stop) to shut down.
func (d *Dispatcher) Start(ctx context.Context) {
	d.ctx, d.cancel = context.WithCancel(ctx)
	d.refresh()
	d.busSub = d.bus.Subscribe(SubjectPattern, d.onEvent)
	d.log.Info("webhook dispatcher started", "pattern", SubjectPattern, "subscriptions", d.count())
}

// Stop unsubscribes from the bus, cancels in-flight attempts and
// backoff waits, and waits up to timeout for workers to finish.
func (d *Dispatcher) Stop(timeout time.Duration) {
	d.stopOnce.Do(func() {
		if d.busSub != nil {
			d.busSub.Cancel()
			d.busSub = nil
		}
		if d.cancel != nil {
			d.cancel()
		}
	})
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		d.log.Warn("webhook dispatcher stop timed out")
	}
}

// onEvent is the single bus subscription: keep the subscription view
// fresh, then fan the event out to matching subscriptions.
func (d *Dispatcher) onEvent(e bus.Event) {
	defer func() {
		if r := recover(); r != nil {
			d.log.Error("webhook dispatcher panic on event", "panic", r)
		}
	}()
	if strings.EqualFold(e.Kind, state.KindSubscription) {
		d.refresh() // created/updated/deleted subscription: sync first
	}
	d.fanout(e)
}

// fanout enqueues the event on every active subscription whose
// spec.subjects match the event subject per the bus grammar.
func (d *Dispatcher) fanout(e bus.Event) {
	d.mu.RLock()
	handles := make([]*subHandle, 0, len(d.subs))
	for _, h := range d.subs {
		handles = append(handles, h)
	}
	d.mu.RUnlock()

	for _, h := range handles {
		view := h.view.Load()
		if view == nil || !view.spec.Active {
			continue
		}
		for _, pattern := range view.spec.Subjects {
			if bus.Match(pattern, e.Subject) {
				d.enqueue(h, e)
				break // one delivery per event per subscription
			}
		}
	}
}

// enqueue places the event on the subscription queue, dropping (with
// an audit entry) when the bounded queue is full.
func (d *Dispatcher) enqueue(h *subHandle, e bus.Event) {
	select {
	case h.queue <- delivery{event: e}:
	default:
		if view := h.view.Load(); view != nil {
			d.audit(view, ActionFailed,
				fmt.Sprintf("%s dropped: subscription queue overflow (>%d pending)", e.Subject, d.opts.QueueSize))
		}
		d.log.Warn("webhook queue overflow, event dropped",
			"subscription", h.id, "subject", e.Subject)
	}
}

// refresh reloads every Subscription resource from the store and
// reconciles the worker pool with it: new subscriptions get a queue
// and worker, updated ones get their view swapped atomically, and
// removed ones get their worker stopped (deliveries cease).
func (d *Dispatcher) refresh() {
	type entry struct {
		res  *state.Resource
		spec state.SubscriptionSpec
	}
	want := map[string]entry{}
	cursor := ""
	for {
		page, next, err := d.store.ListResources(state.ListOptions{
			Kind: state.KindSubscription, Limit: 200, Cursor: cursor,
		})
		if err != nil {
			d.log.Error("webhook subscription refresh failed", "err", err)
			return
		}
		for _, r := range page {
			spec, err := state.ParseSubscriptionSpec(r.Spec)
			if err != nil {
				// Validate() should have rejected this at the door;
				// skip rather than deliver to a broken spec.
				d.log.Warn("skipping subscription with invalid spec", "id", r.ID, "err", err)
				continue
			}
			want[r.ID] = entry{res: r, spec: spec}
		}
		if next == "" {
			break
		}
		cursor = next
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for id, h := range d.subs {
		if _, keep := want[id]; keep {
			continue
		}
		close(h.quit) // worker exits; buffered events are abandoned
		delete(d.subs, id)
	}
	for id, w := range want {
		view := &subView{res: w.res, spec: w.spec, secret: d.secretFor(id)}
		if h, ok := d.subs[id]; ok {
			h.view.Store(view)
			continue
		}
		h := &subHandle{
			id:    id,
			queue: make(chan delivery, d.opts.QueueSize),
			quit:  make(chan struct{}),
		}
		h.view.Store(view)
		d.subs[id] = h
		d.wg.Add(1)
		go d.work(h)
	}
}

// work drains one subscription's queue until the subscription is
// removed or the dispatcher shuts down.
func (d *Dispatcher) work(h *subHandle) {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			d.log.Error("webhook worker panic", "subscription", h.id, "panic", r)
		}
	}()
	for {
		// Quit takes priority so removal/shutdown is prompt even
		// with deliveries still buffered.
		select {
		case <-d.ctx.Done():
			return
		case <-h.quit:
			return
		default:
		}
		select {
		case <-d.ctx.Done():
			return
		case <-h.quit:
			return
		case del := <-h.queue:
			d.process(h, del)
		}
	}
}

// process performs the delivery with retries: one attempt now, then
// exponential backoff up to spec.MaxRetries total attempts, auditing
// every attempt outcome.
func (d *Dispatcher) process(h *subHandle, del delivery) {
	view := h.view.Load()
	if view == nil {
		return
	}
	body, err := json.Marshal(deliveryPayload{Event: del.event, SubscriptionID: h.id})
	if err != nil {
		// Events are plain JSON data; marshal failure is a bug.
		d.log.Error("webhook payload marshal failed", "subscription", h.id, "err", err)
		return
	}

	total := view.spec.MaxRetries + 1 // initial attempt + retries
	for attempt := 1; ; attempt++ {
		view = h.view.Load() // spec (url/secret) may have been updated
		if view == nil {
			return
		}
		if d.attempt(view, body, del.event, h.id) {
			d.audit(view, ActionDelivered,
				fmt.Sprintf("%s attempt %d/%d", del.event.Subject, attempt, total))
			d.log.Debug("webhook delivered",
				"subscription", h.id, "subject", del.event.Subject, "attempt", attempt)
			return
		}
		d.audit(view, ActionFailed,
			fmt.Sprintf("%s attempt %d/%d", del.event.Subject, attempt, total))
		if attempt >= total {
			d.log.Warn("webhook delivery failed permanently",
				"subscription", h.id, "subject", del.event.Subject, "attempts", attempt)
			return
		}
		if !d.wait(d.ctx, d.backoff(attempt)) {
			return // shutting down mid-backoff
		}
	}
}

// attempt performs one signed POST; success is any 2xx response
// within the request timeout.
func (d *Dispatcher) attempt(view *subView, body []byte, e bus.Event, subID string) bool {
	ctx, cancel := context.WithTimeout(d.ctx, d.opts.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, view.spec.URL, bytes.NewReader(body))
	if err != nil {
		d.log.Warn("webhook request build failed", "url", view.spec.URL, "err", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ryvex-Signature", sign(view.secret, body))
	req.Header.Set("X-Ryvex-Event-ID", e.ID)
	req.Header.Set("X-Ryvex-Subscription-ID", subID)

	resp, err := d.opts.Client.Do(req)
	if err != nil {
		d.log.Debug("webhook attempt failed", "url", view.spec.URL, "err", err)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// backoff returns the wait before the retry following attempt n:
// base, 2*base, 4*base, ... capped at MaxBackoff.
func (d *Dispatcher) backoff(attempt int) time.Duration {
	base := d.opts.BackoffBase
	shift := attempt - 1
	if shift > 20 { // guard shift overflow; MaxBackoff binds long before this
		return MaxBackoff
	}
	dur := base << uint(shift)
	if dur <= 0 || dur > MaxBackoff {
		return MaxBackoff
	}
	return dur
}

// wait sleeps for dur, returning false when ctx was cancelled first.
func (d *Dispatcher) wait(ctx context.Context, dur time.Duration) bool {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// audit appends a delivery-outcome entry referencing the subscription.
func (d *Dispatcher) audit(view *subView, action, reason string) {
	_ = d.store.AppendAudit(state.AuditEntry{
		Time:       d.opts.Clock().UTC(),
		Actor:      AuditActor,
		Action:     action,
		ResourceID: view.res.ID,
		Kind:       view.res.Kind,
		LogicalKey: view.res.LogicalKey(),
		Generation: view.res.Generation,
		Reason:     reason,
	})
}

// secretFor derives the per-subscription signing secret:
// hex(HMAC-SHA256(serverSecret, subscriptionID)).
func (d *Dispatcher) secretFor(subscriptionID string) string {
	mac := hmac.New(sha256.New, []byte(d.opts.ServerSecret))
	mac.Write([]byte(subscriptionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// sign computes the X-Ryvex-Signature header value over the raw body.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (d *Dispatcher) count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.subs)
}
