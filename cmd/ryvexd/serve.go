package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/api"
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
			return fmt.Errorf("nats event bus: %w (check --nats-url / RYVEX_NATS_URL; refusing to fall back to the memory bus)", err)
		}
		defer nb.Close()
		eventBus = nb
		log.Info("event bus: NATS JetStream", "url", *natsURL, "stream", natsbus.StreamName)
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

	handler := api.NewServer(store, eventBus, reconciler, api.ServerOptions{
		Auth:        auth,
		Logger:      log,
		CORSOrigins: splitCommaList(*corsOrigins),
	})
	srv := &http.Server{
		Addr:              *httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	recCtx, recCancel := context.WithCancel(ctx)
	defer recCancel()
	reconciler.Start(recCtx)
	dispatcher.Start(recCtx) // --- webhooks (issue #13) ---

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
		metricsSrv = &http.Server{
			Addr:              *metricsAddr,
			Handler:           mmux,
			ReadHeaderTimeout: 10 * time.Second,
		}
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
