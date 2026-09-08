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
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
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
	seed := fs.Bool("seed", false, "load the demo dataset on boot")
	logLevel := fs.String("log-level", "info", "log level")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log, err := newLogger(*logLevel)
	if err != nil {
		return err
	}

	if *storeKind != "memory" {
		return fmt.Errorf("unsupported store %q (only \"memory\" is available in this build)", *storeKind)
	}
	store := state.NewStore()
	eventBus := bus.New()

	// Replay recent control-plane events into the log for visibility.
	eventBus.Subscribe("ryvex.resource.>", func(e bus.Event) {
		log.Debug("event", "subject", e.Subject, "type", e.Type, "resource", e.Kind+"/"+e.Name)
	})

	reconciler := reconcile.New(store, eventBus, reconcile.Options{
		Interval:    30 * time.Second,
		Concurrency: 4,
		Logger:      log,
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

	handler := api.NewServer(store, eventBus, reconciler, api.ServerOptions{Auth: auth, Logger: log})
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

	if *seed {
		n, err := seedDemoData(ctx, store, log)
		if err != nil {
			return fmt.Errorf("seeding demo data: %w", err)
		}
		log.Info("demo dataset loaded", "resources", n)
	}

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
	recCancel()
	reconciler.Stop(3 * time.Second)
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
