package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/api"
	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus/natsbus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
	"github.com/Roy-Wanyoike/Ryvex/internal/state/pgstore"
	"github.com/Roy-Wanyoike/Ryvex/internal/webhook"
)

// runServe boots the full control plane stack:
//
//	store -> event bus -> reconciler -> HTTP server
//
// and blocks until an interrupt signal triggers graceful shutdown.
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	httpAddr := fs.String("http", envOr("RYVEX_HTTP_ADDR", ":8080"), "HTTP listen address")
	storeKind := fs.String("store", "memory", "state backend (memory)")
	devAuth := fs.Bool("dev-auth", false, "accept any ryk_ bearer token (development only)")
	apiKeys := fs.String("api-keys", envOr("RYVEX_API_KEYS", ""), "static API keys as name=token,comma-separated")
	corsOrigins := fs.String("cors-origins", envOr("RYVEX_CORS_ORIGINS", ""), "browser origins allowed to call the API, comma-separated")
	seed := fs.Bool("seed", false, "load the demo dataset on boot")
	// Metrics sidecar (issue #17): empty disables the endpoint.
	metricsAddr := fs.String("metrics-addr", envOr("RYVEX_METRICS_ADDR", ""), "dedicated listen address for /metrics and /healthz passthrough (empty disables metrics)")
	logLevel := fs.String("log-level", "info", "log level")
	// --- postgres store (issue #14): DSN flag ---
	dsn := fs.String("dsn", envOr("RYVEX_DATABASE_URL", ""), "Postgres DSN (required when --store=postgres)")
	// --- webhooks (issue #13): signing-secret flag ---
	webhookSecret := fs.String("webhook-secret", envOr("RYVEX_WEBHOOK_SECRET", ""), "HMAC key material for webhook signatures (random per boot when unset)")
	// --- nats bus (issue #15): durable event bus flags ---
	busKind := fs.String("bus", "memory", "event bus backend: memory (default) or nats (JetStream)")
	natsURL := fs.String("nats-url", envOr("RYVEX_NATS_URL", "nats://127.0.0.1:4222"), "NATS server URL used when --bus=nats")
	// --- end nats bus flags ---
	if err := fs.Parse(args); err != nil {
		return err
	}

	log, err := newLogger(*logLevel)
	if err != nil {
		return err
	}

	// --- dev-auth guard (issue #38) ---
	// --dev-auth grants full admin to any well-formed ryk_ token;
	// combined with a durable store/bus it is almost always a
	// mistake, so refuse to boot unless explicitly overridden.
	if err := checkDevAuthGuard(*devAuth, *storeKind, *busKind); err != nil {
		return err
	}
	if *devAuth && !isLoopbackListenAddr(*httpAddr) {
		log.Warn("DEV-AUTH LISTENING ON A NON-LOOPBACK ADDRESS: any ryk_ bearer token " +
			"gets full admin access from any network that can reach " + *httpAddr +
			"; use --dev-auth only on 127.0.0.1/localhost")
	}
	// --- end dev-auth guard ---

	// --- postgres store (issue #14): backend selection ---
	var store state.Backend
	switch *storeKind {
	case "memory":
		store = state.NewStore()
	case "postgres":
		if *dsn == "" {
			return fmt.Errorf("--store postgres requires --dsn (or env RYVEX_DATABASE_URL)")
		}
		pgs, err := pgstore.NewStore(*dsn)
		if err != nil {
			return fmt.Errorf("postgres store: %w", err)
		}
		defer pgs.Close()
		mctx, mcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer mcancel()
		if err := pgs.Migrate(mctx); err != nil {
			return fmt.Errorf("postgres migrate: %w", err)
		}
		store = pgs
	default:
		return fmt.Errorf("unsupported store %q (available: \"memory\", \"postgres\")", *storeKind)
	}
	// --- end postgres store (issue #14) ---
	// --- nats bus (issue #15): backend selection ---
	// Memory is the default. --bus=nats dials JetStream and fails AT
	// BOOT on connect errors: once durability was explicitly requested
	// there is never a silent fallback to the in-memory bus.
	var eventBus bus.BusI
	switch *busKind {
	case "memory", "":
		eventBus = bus.New()
	case "nats":
		nb, err := natsbus.New(*natsURL, natsbus.Options{Logger: log})
		if err != nil {
			// Scrub credentials from the connect error before
			// wrapping (issue #38): natsbus embeds the raw URL.
			return fmt.Errorf("nats event bus: %w (check --nats-url / RYVEX_NATS_URL; refusing to fall back to the memory bus)", &redactedError{err: err, raw: *natsURL})
		}
		defer nb.Close()
		eventBus = nb
		// Never log the URL raw: it may carry user:pass userinfo (issue #38).
		log.Info("event bus: NATS JetStream", "url", redactURL(*natsURL), "stream", natsbus.StreamName)
	default:
		return fmt.Errorf("unsupported bus %q (want \"memory\" or \"nats\")", *busKind)
	}
	// --- end nats bus ---

	// Replay recent control-plane events into the log for visibility.
	eventBus.Subscribe("ryvex.resource.>", func(e bus.Event) {
		log.Debug("event", "subject", e.Subject, "type", e.Type, "resource", e.Kind+"/"+e.Name)
	})

	reconciler := reconcile.New(store, eventBus, reconcile.Options{
		Interval:    30 * time.Second,
		Concurrency: 4,
		Logger:      log,
	})

	// --- webhooks (issue #13): event dispatcher ---
	dispatcher := webhook.NewDispatcher(store, eventBus, webhook.Options{
		ServerSecret: *webhookSecret,
		Logger:       log,
	})

	auth := api.AuthOptions{DevAuth: *devAuth, APIKeys: map[string]string{}}
	for _, kv := range strings.Split(*apiKeys, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, tok, ok := strings.Cut(kv, "=")
		if !ok || name == "" || tok == "" {
			return fmt.Errorf("invalid --api-keys entry %q (want name=token)", kv)
		}
		auth.APIKeys[tok] = name
	}
	if !*devAuth && len(auth.APIKeys) == 0 {
		log.Warn("no API keys configured and --dev-auth is off; all /v1 requests will be rejected")
	}

	// --- RBAC (issue #16): authorizer + bootstrap of static admin keys ---
	// Static --api-keys entries are registered as admin key resources
	// (principal=name, roles=[admin], scopes=["org/*"]) so they show up
	// in GET /v1/keys; the static fallback in AuthZMiddleware keeps them
	// working even if the store lost them.
	authorizer := authz.New(store, eventBus, authz.Options{Logger: log})
	for name, tok := range auth.APIKeys {
		if err := api.SeedAdminKey(store, name, tok, log); err != nil {
			log.Warn("bootstrap admin key not registered", "principal", name, "err", err)
		}
	}
	if err := authorizer.Refresh(); err != nil {
		log.Error("authz key cache bootstrap failed", "err", err)
	}
	// --- end RBAC (issue #16) ---

	handler := api.NewServer(store, eventBus, reconciler, api.ServerOptions{
		Auth:        auth,
		Logger:      log,
		CORSOrigins: splitCommaList(*corsOrigins),
		Authorizer:  authorizer,
		Version:     Version, // plumbed to /healthz and the /v1 index (issue #38)
	})
	srv := newHTTPServer(*httpAddr, handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	recCtx, recCancel := context.WithCancel(ctx)
	defer recCancel()
	reconciler.Start(recCtx)
	dispatcher.Start(recCtx) // --- webhooks (issue #13) ---
	authorizer.Start(recCtx) // --- RBAC (issue #16): periodic cache refresh ---

	if *seed {
		n, err := seedDemoData(ctx, store, log)
		if err != nil {
			return fmt.Errorf("seeding demo data: %w", err)
		}
		log.Info("demo dataset loaded", "resources", n)
	}

	// ---- metrics sidecar (issue #17) ----
	// A tiny separate server on --metrics-addr exposing /metrics (the
	// default Prometheus registry in text exposition format v0.0.4)
	// plus a status-only /healthz passthrough. It never touches the
	// main mux; bind failures are logged and non-fatal.
	var metricsSrv *http.Server
	if *metricsAddr != "" {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", metrics.Handler())
		mmux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		metricsSrv = newHTTPServer(*metricsAddr, mmux)
		go func() {
			log.Info("metrics endpoint listening", "addr", *metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics endpoint failed", "err", err)
			}
		}()
	}
	// ---- end metrics sidecar ----

	errCh := make(chan error, 1)
	go func() {
		log.Info("ryvexd listening", "addr", *httpAddr, "version", Version, "dev_auth", *devAuth)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shCtx)
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shCtx) // metrics sidecar shuts down alongside the main server
	}
	recCancel()
	reconciler.Stop(3 * time.Second)
	dispatcher.Stop(3 * time.Second) // --- webhooks (issue #13) ---
	// --- nats bus (issue #15): drain subscriptions + connection ---
	if closer, ok := eventBus.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	// --- end nats bus ---
	log.Info("ryvexd stopped cleanly")
	return nil
}

// checkDevAuthGuard refuses to boot when --dev-auth is combined with a
// durable backend (issue #38): any well-formed ryk_ token gets full
// admin, and pairing that with postgres or JetStream is almost always
// an accident of copying a dev command line into staging. The env
// escape hatch RYVEX_ALLOW_DEV_AUTH=1 documents deliberate intent.
func checkDevAuthGuard(devAuth bool, storeKind, busKind string) error {
	if !devAuth {
		return nil
	}
	durable := storeKind == "postgres" || busKind == "nats"
	if !durable {
		return nil
	}
	if envOr("RYVEX_ALLOW_DEV_AUTH", "") == "1" {
		return nil
	}
	return fmt.Errorf(
		"--dev-auth cannot be combined with --store postgres or --bus nats: any ryk_ bearer token would receive full admin access to durable state; set RYVEX_ALLOW_DEV_AUTH=1 to override",
	)
}

// isLoopbackListenAddr reports whether addr listens only on a loopback
// interface. Blank or wildcard hosts ("":8080", "0.0.0.0", "::") are
// NOT loopback — they expose the listener to every interface.
func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // bare host/IP without a port
	}
	switch host {
	case "", "0.0.0.0", "::":
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname: only the explicit loopback names are trusted.
		return host == "localhost"
	}
	return ip.IsLoopback()
}

// redactURL reduces a connection URL to scheme://host[:port], dropping
// userinfo and query strings so credentials never reach logs
// (issue #38). Degenerate parses that cannot be redacted structurally
// (opaque strings, embedded credentials) collapse to "(redacted)".
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(redacted)"
	}
	if u.Host == "" {
		// No authority to speak of (e.g. "nats.example:4222" parsed as
		// scheme+opaque). Return as-is only when there is nothing that
		// looks like credentials anywhere in the string.
		if strings.Contains(raw, "@") {
			return "(redacted)"
		}
		return raw
	}
	if u.Scheme == "" {
		return u.Host
	}
	return u.Scheme + "://" + u.Host
}

// stripUserinfo removes "user:pass@" credentials from every authority
// embedded in s, however the URL is rendered (with/without trailing
// slash, multiple URLs, alternate quoting). Used as the belt-and-braces
// pass behind the exact-match replacement.
func stripUserinfo(s string) string {
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], "://")
		if j < 0 {
			return s
		}
		start := i + j + 3
		end := start
		for end < len(s) && !strings.ContainsRune("/?#", rune(s[end])) {
			end++
		}
		auth := s[start:end]
		if at := strings.LastIndex(auth, "@"); at >= 0 {
			s = s[:start] + auth[at+1:] + s[end:]
			i = start // the authority shrank; rescan from the same spot
		} else {
			i = end // nothing to strip; look for the next authority
		}
	}
	return s
}

// scrubURL removes credential-bearing forms of raw from s: the URL
// itself is replaced by its redacted form, then any userinfo that
// survives in other renderings of the URL is stripped.
func scrubURL(s, raw string) string {
	return stripUserinfo(strings.ReplaceAll(s, raw, redactURL(raw)))
}

// redactedError wraps an error whose message may embed credentials,
// redacting them in Error() while preserving the wrap chain for
// errors.Is / errors.As.
type redactedError struct {
	err error
	raw string // credential-bearing URL to scrub
}

func (e *redactedError) Error() string { return scrubURL(e.err.Error(), e.raw) }
func (e *redactedError) Unwrap() error { return e.err }

// newHTTPServer builds an http.Server with the production timeout
// posture (issue #38): slowloris-resistant read timeouts, bounded
// idle connections, and a 1 MiB header cap. Used for both the main
// control-plane server and the metrics sidecar.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func newLogger(level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q", level)
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h), nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitCommaList parses "a,b,c" into clean parts, dropping empties.
func splitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
