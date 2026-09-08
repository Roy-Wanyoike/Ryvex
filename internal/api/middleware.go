package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyActor
)

// TokenPrefix is the namespace for Ryvex API keys.
const TokenPrefix = "ryk_"

// RequestIDMiddleware assigns a short request ID to every request and
// echoes it back in X-Request-Id.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var b [6]byte
			_, _ = rand.Read(b[:])
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

// RequestIDFrom extracts the request ID from a request context.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// ActorFrom extracts the authenticated principal for a request.
func ActorFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyActor).(string); ok {
		return v
	}
	return ""
}

// RecoverMiddleware converts handler panics into 500s so a bug in one
// route cannot take down the daemon.
func RecoverMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if log != nil {
						log.Error("panic in handler", "err", fmt.Sprint(rec), "path", r.URL.Path, "request_id", RequestIDFrom(r.Context()))
					}
					writeError(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// LogMiddleware emits one structured line per request.
func LogMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			if log != nil {
				log.Info("http",
					"method", r.Method,
					"path", r.URL.Path,
					"status", sw.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"actor", ActorFrom(r.Context()),
					"request_id", RequestIDFrom(r.Context()),
				)
			}
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// AuthOptions configures bearer-token authentication.
type AuthOptions struct {
	// APIKeys maps bearer tokens to principal names.
	APIKeys map[string]string
	// DevAuth, when true, accepts any well-formed ryk_ token. It is a
	// development affordance and must be disabled in production.
	DevAuth bool
	// Skip paths are authenticated elsewhere (e.g. /healthz).
	SkipPrefixes []string
}

// CORSMiddleware enables cross-origin browser clients (the web
// console) to call the API. Only explicitly allowed origins get
// headers; preflight requests short-circuit before auth.
func CORSMiddleware(allowed []string) func(http.Handler) http.Handler {
	allowedSet := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		allowedSet[strings.TrimSpace(o)] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowedSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions && origin != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware enforces bearer authentication.
func AuthMiddleware(opts AuthOptions, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range opts.SkipPrefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			actor, ok := authenticate(r, opts)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ryvex"`)
				writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "missing or invalid bearer token (expected ryk_ API key)")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyActor, actor)))
		})
	}
}

func authenticate(r *http.Request, opts AuthOptions) (string, bool) {
	h := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if !strings.HasPrefix(h, bearer) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, bearer))
	if tok == "" {
		return "", false
	}
	if name, ok := opts.APIKeys[tok]; ok {
		return name, true
	}
	if opts.DevAuth && strings.HasPrefix(tok, TokenPrefix) && len(tok) > len(TokenPrefix)+3 {
		return "dev:" + tok[len(TokenPrefix):], true
	}
	return "", false
}

// ConstantTimeEqual is exported for key comparison in custom auth hooks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
