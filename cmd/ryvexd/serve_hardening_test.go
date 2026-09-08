package main

// Tests for the ryvexd hardening batch (issue #38): the dev-auth boot
// guard, listen-address classification, NATS URL redaction, and the
// production http.Server timeout posture.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCheckDevAuthGuard(t *testing.T) {
	cases := []struct {
		name      string
		devAuth   bool
		storeKind string
		busKind   string
		wantErr   bool
	}{
		{"dev-auth off is always fine", false, "postgres", "nats", false},
		{"dev-auth with memory store+bus is fine", true, "memory", "memory", false},
		{"dev-auth with empty bus kind is fine", true, "memory", "", false},
		{"dev-auth + postgres refused", true, "postgres", "memory", true},
		{"dev-auth + nats refused", true, "memory", "nats", true},
		{"dev-auth + postgres + nats refused", true, "postgres", "nats", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkDevAuthGuard(c.devAuth, c.storeKind, c.busKind)
			if c.wantErr && err == nil {
				t.Fatalf("expected refusal for --dev-auth + %s/%s", c.storeKind, c.busKind)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "RYVEX_ALLOW_DEV_AUTH") {
				t.Fatalf("refusal must name the escape hatch, got: %v", err)
			}
		})
	}
}

func TestCheckDevAuthGuardEnvOverride(t *testing.T) {
	t.Setenv("RYVEX_ALLOW_DEV_AUTH", "1")
	if err := checkDevAuthGuard(true, "postgres", "nats"); err != nil {
		t.Fatalf("RYVEX_ALLOW_DEV_AUTH=1 must allow the boot, got: %v", err)
	}
}

func TestRunServeRefusesDevAuthWithDurableBackends(t *testing.T) {
	// Through the real flag surface: the guard fires before any store
	// or bus construction, so these return without touching the network.
	err := runServe([]string{"--dev-auth", "--store", "postgres"})
	if err == nil || !strings.Contains(err.Error(), "RYVEX_ALLOW_DEV_AUTH") {
		t.Fatalf("--dev-auth --store postgres must be refused at boot, got: %v", err)
	}

	err = runServe([]string{"--dev-auth", "--bus", "nats"})
	if err == nil || !strings.Contains(err.Error(), "RYVEX_ALLOW_DEV_AUTH") {
		t.Fatalf("--dev-auth --bus nats must be refused at boot, got: %v", err)
	}

	// With the override set the guard passes and boot proceeds past it
	// (it then fails later on the missing --dsn — proving the guard is
	// no longer the blocker).
	t.Setenv("RYVEX_ALLOW_DEV_AUTH", "1")
	err = runServe([]string{"--dev-auth", "--store", "postgres"})
	if err == nil || strings.Contains(err.Error(), "RYVEX_ALLOW_DEV_AUTH") {
		t.Fatalf("override must clear the guard; got: %v", err)
	}
	if !strings.Contains(err.Error(), "--dsn") {
		t.Fatalf("expected the store's own --dsn error after the guard, got: %v", err)
	}
}

func TestIsLoopbackListenAddr(t *testing.T) {
	cases := map[string]bool{
		":8080":           false, // all interfaces
		"0.0.0.0:8080":    false,
		"[::]:8080":       false,
		"10.1.2.3:8080":   false,
		"example.com:443": false,
		"127.0.0.1:8080":  true,
		"[::1]:8080":      true,
		"localhost:9000":  true,
		"127.0.0.1":       true, // bare host without port
	}
	for addr, want := range cases {
		if got := isLoopbackListenAddr(addr); got != want {
			t.Errorf("isLoopbackListenAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"nats://alice:s3cret@nats.example:4222":                "nats://nats.example:4222",
		"nats://nats.example:4222":                             "nats://nats.example:4222",
		"postgres://u:p@db.example:5432/ryvex?sslmode=require": "postgres://db.example:5432",
		"tls://user@host:7422":                                 "tls://host:7422",
		"nats.example:4222":                                    "nats.example:4222", // opaque, no creds to hide
		"user:pass@host:4222":                                  "(redacted)",        // opaque with creds
	}
	for raw, want := range cases {
		if got := redactURL(raw); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestScrubURLAndRedactedError(t *testing.T) {
	const raw = "nats://alice:s3cret@nats.example:4222"
	inner := errors.New("natsbus: connect " + raw + ": connection refused")
	wrapped := &redactedError{err: inner, raw: raw}

	got := wrapped.Error()
	if strings.Contains(got, "s3cret") || strings.Contains(got, "alice") {
		t.Fatalf("wrapped error still leaks credentials: %s", got)
	}
	if !strings.Contains(got, "nats://nats.example:4222") || !strings.Contains(got, "connection refused") {
		t.Fatalf("redacted error lost the useful message: %s", got)
	}

	// The wrap chain survives for errors.Is/As.
	sentinel := errors.New("natsbus: root cause")
	chained := &redactedError{err: sentinel, raw: raw}
	if !errors.Is(chained, sentinel) {
		t.Fatalf("redactedError must preserve Unwrap")
	}

	// Alternate renderings (trailing slash) are caught by the
	// userinfo-stripping pass.
	if got := scrubURL("dial nats://alice:s3cret@nats.example:4222/ failed", "nats://nats.example:4222"); strings.Contains(got, "s3cret") {
		t.Fatalf("userinfo survived scrubbing: %s", got)
	}
}

func TestNewHTTPServerTimeoutPosture(t *testing.T) {
	srv := newHTTPServer(":0", http.NotFoundHandler())
	if srv.Addr != ":0" {
		t.Fatalf("addr not wired: %q", srv.Addr)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want 1MiB", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s (pre-existing)", srv.ReadHeaderTimeout)
	}
}

// The usage text must stay in sync with the serve flag set
// (issue #38 item 11): all 12 flags listed.
func TestUsageListsAllServeFlags(t *testing.T) {
	for _, f := range []string{
		"--http", "--store", "--dsn", "--bus", "--nats-url",
		"--dev-auth", "--api-keys", "--cors-origins", "--webhook-secret",
		"--metrics-addr", "--seed", "--log-level",
	} {
		if !strings.Contains(usage, f) {
			t.Errorf("usage text is missing the %s flag", f)
		}
	}
	if !strings.Contains(usage, "postgres") {
		t.Errorf("usage must mention the postgres store option")
	}
	if !strings.Contains(usage, "RYVEX_ALLOW_DEV_AUTH") {
		t.Errorf("usage must document the dev-auth escape hatch")
	}
}
