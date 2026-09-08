package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyActor
	ctxKeyIdentity
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

// Identity is the authenticated caller attached to the request
// context by AuthZMiddleware (issue #16). Admin is true for keys
// carrying the admin role, for static bootstrap keys and in dev-auth
// mode.
type Identity struct {
	Principal string
	Roles     []string
	Admin     bool
}

// IdentityFrom extracts the RBAC identity from a request context.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	if v, ok := ctx.Value(ctxKeyIdentity).(Identity); ok {
		return v, true
	}
	return Identity{}, false
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

// LogMiddleware emits one structured line per request and records
// the HTTP request counter and duration histogram (issue #17). Route
// labels are low-cardinality buckets from routeLabel, never raw paths.
func LogMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			route := routeLabel(r.URL.Path)
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			duration := time.Since(start)
			metrics.HTTPRequestsTotal.WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).Inc()
			metrics.HTTPRequestDuration.WithLabelValues(route, r.Method).Observe(duration.Seconds())
			if log != nil {
				log.Info("http",
					"method", r.Method,
					"path", r.URL.Path,
					"status", sw.status,
					"duration_ms", duration.Milliseconds(),
					"actor", ActorFrom(r.Context()),
					"request_id", RequestIDFrom(r.Context()),
				)
			}
		})
	}
}

// routeLabel normalizes a request path into a fixed set of route
// buckets so metrics cardinality stays bounded no matter how many
// orgs/kinds/ids are addressed. The buckets mirror the routeV1
// dispatch cases: parameters are replaced by placeholders.
func routeLabel(path string) string {
	switch path {
	case "/healthz":
		return "healthz"
	case "/", "/v1", "/v1/":
		return "index"
	}
	trimmed := strings.Trim(strings.TrimPrefix(path, "/v1"), "/")
	seg := strings.Split(trimmed, "/")
	switch {
	case seg[0] == "resources" && len(seg) == 1:
		return "resources"
	case seg[0] == "resources" && len(seg) == 2:
		return "resources/{id}"
	case seg[0] == "keys" && len(seg) == 1:
		return "keys"
	case seg[0] == "keys" && len(seg) == 2:
		return "keys/{id}"
	case len(seg) == 2 && seg[1] == "events":
		return "org/events"
	case len(seg) == 2 && seg[1] == "audit":
		return "org/audit"
	case len(seg) == 3 && seg[1] == "reconcile":
		return "org/reconcile/{id}"
	case len(seg) == 4:
		return "scope/{kind}"
	case len(seg) == 5:
		return "scope/{kind}/{name}"
	default:
		return "other"
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
	// APIKeys maps bearer tokens to principal names. Tokens are
	// hashed once at boot (see staticKeyIndex) — this map is only
	// read during construction, never compared per request.
	APIKeys map[string]string
	// DevAuth, when true, accepts any well-formed ryk_ token. It is a
	// development affordance and must be disabled in production.
	DevAuth bool
	// Skip paths are authenticated elsewhere (e.g. /healthz).
	SkipPrefixes []string
}

// staticKeyIndex holds the sha256 digests of the static bootstrap
// tokens, keyed digest→principal (issue #38). Plain map lookups on raw
// tokens leak key material through timing; hashing first and deciding
// with a constant-time digest compare matches the managed-key path
// (authz.go).
type staticKeyEntry struct {
	principal string
	digest    string // sha256 hex of the token
}

// staticKeyIndex is safe for concurrent use: it is built once at
// server construction and only read afterwards.
type staticKeyIndex struct {
	byDigest map[string]staticKeyEntry // sha256 hex digest -> entry
	dummy    string                    // compare target when no candidate hits
}

// newStaticKeyIndex hashes every bootstrap token once. Called at
// server construction — never per request.
func newStaticKeyIndex(keys map[string]string) staticKeyIndex {
	ix := staticKeyIndex{
		byDigest: make(map[string]staticKeyEntry, len(keys)),
		dummy:    authz.HashToken("ryvex-digest-compare-sink"),
	}
	for tok, name := range keys {
		if tok == "" {
			continue
		}
		digest := authz.HashToken(tok)
		ix.byDigest[digest] = staticKeyEntry{principal: name, digest: digest}
	}
	return ix
}

// lookup authenticates a presented token against the digest index.
// The token is hashed and the digest looked up (O(1) candidate
// selection); the decision is then made with exactly one constant-time
// comparison of the presented digest against the stored digest (hit)
// or the dummy (miss), so response timing never depends on the token
// bytes.
func (ix staticKeyIndex) lookup(token string) (string, bool) {
	digest := authz.HashToken(token)
	entry, hit := ix.byDigest[digest]
	target := ix.dummy
	if hit {
		target = entry.digest
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(target)) != 1 {
		return "", false
	}
	if !hit {
		return "", false
	}
	return entry.principal, true
}

// authenticateToken resolves a presented token to a principal via the
// static digest index, then dev-auth. Shared by the legacy
// AuthMiddleware and /healthz probe classification.
func authenticateToken(tok string, ix staticKeyIndex, devAuth bool) (string, bool) {
	if name, ok := ix.lookup(tok); ok {
		return name, true
	}
	if devAuth && strings.HasPrefix(tok, TokenPrefix) && len(tok) > len(TokenPrefix)+3 {
		return "dev:" + tok[len(TokenPrefix):], true
	}
	return "", false
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

// SecurityHeadersMiddleware sets conservative response headers
// (issue #38): browsers must never sniff bodies into another content
// type or frame the API, and /v1 responses are never cacheable.
// /healthz stays simple — it only gains nosniff/DENY, not caching
// directives.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/v1") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware enforces bearer authentication (legacy mode; kept
// for compatibility). When an RBAC authorizer is wired (issue #16)
// NewServer uses AuthZMiddleware instead.
func AuthMiddleware(opts AuthOptions, log *slog.Logger) func(http.Handler) http.Handler {
	// Hash the static tokens once at construction (issue #38).
	ix := newStaticKeyIndex(opts.APIKeys)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range opts.SkipPrefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			tok, ok := bearerToken(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ryvex"`)
				writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "missing or invalid bearer token (expected ryk_ API key)")
				return
			}
			actor, ok := authenticateToken(tok, ix, opts.DevAuth)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ryvex"`)
				writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "missing or invalid bearer token (expected ryk_ API key)")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyActor, actor)))
		})
	}
}

// bearerToken extracts the token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if !strings.HasPrefix(h, bearer) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, bearer))
	if tok == "" {
		return "", false
	}
	return tok, true
}

// ConstantTimeEqual is exported for key comparison in custom auth hooks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---- RBAC enforcement (issue #16) ----

// requestScope is the authorization target derived from a request.
type requestScope struct {
	org, project string
	write        bool
	pass         bool // no scope check (index, key management routes)
	adminOnly    bool // restricted to admin keys (scope not derivable)
}

// AuthZMiddleware enforces authentication plus org/project-scoped
// RBAC (issue #16). /healthz stays open. Tokens resolve in order:
// managed keys (authorizer), then static APIKeys (treated as admin;
// compared as sha256 digests, issue #38), then — when devAuth is set —
// any well-formed ryk_ token (full access, logged through the
// injected logger). The org/project target comes from the path
// (segment counts), the query string, or — for POST /v1/resources —
// the JSON body, which is read once here and reinjected for the
// handler. Denials are 403 envelopes with code "forbidden" and land
// in the audit log as authz_denied.
func AuthZMiddleware(az *authz.Authorizer, opts AuthOptions, log *slog.Logger) func(http.Handler) http.Handler {
	// Hash the static tokens once at construction (issue #38).
	ix := newStaticKeyIndex(opts.APIKeys)
	devAuth := opts.DevAuth
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/healthz/") {
				next.ServeHTTP(w, r)
				return
			}
			tok, ok := bearerToken(r)
			if !ok {
				unauthorized(w, r)
				return
			}
			var ident Identity
			switch principal, info, kind := resolveToken(az, ix, devAuth, tok); kind {
			case tokenManaged:
				ident = Identity{Principal: principal, Roles: info.Roles, Admin: authz.HasRole(info.Roles, state.RoleAdmin)}
			case tokenStatic:
				ident = Identity{Principal: principal, Admin: true}
			case tokenDev:
				ident = Identity{Principal: principal, Admin: true}
				// Routed through the injected logger, not
				// slog.Default() (issue #38).
				log.Info("authz", "mode", "dev", "principal", ident.Principal, "path", r.URL.Path)
			default:
				unauthorized(w, r)
				return
			}

			r = r.WithContext(context.WithValue(
				context.WithValue(r.Context(), ctxKeyActor, ident.Principal),
				ctxKeyIdentity, ident,
			))

			scope, handled := deriveScope(w, r)
			if handled {
				return // response already written (413 oversized body)
			}
			if scope.pass {
				next.ServeHTTP(w, r)
				return
			}
			if !ident.Admin {
				var reason string
				if scope.adminOnly {
					reason = "admin role required on this route"
				} else if d := az.Authorize(ident.Principal, scope.org, scope.project, scope.write); !d.Allowed {
					reason = d.Reason
				}
				if reason != "" {
					writeError(w, r, http.StatusForbidden, CodeForbidden, reason)
					az.AuditDenied(ident.Principal, scope.org, scope.project, r.Method, r.URL.Path, reason)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type tokenKind int

const (
	tokenUnknown tokenKind = iota
	tokenManaged
	tokenStatic
	tokenDev
)

// resolveToken authenticates a token against managed keys, static
// key digests, and (when enabled) dev-auth — mirroring the legacy order.
func resolveToken(az *authz.Authorizer, static staticKeyIndex, devAuth bool, tok string) (principal string, info authz.KeyInfo, kind tokenKind) {
	if p, ok := az.Authenticate(tok); ok {
		info, _ = az.Lookup(p)
		return p, info, tokenManaged
	}
	if name, ok := static.lookup(tok); ok {
		return name, authz.KeyInfo{}, tokenStatic
	}
	if devAuth && strings.HasPrefix(tok, TokenPrefix) && len(tok) > len(TokenPrefix)+3 {
		return "dev:" + tok[len(TokenPrefix):], authz.KeyInfo{}, tokenDev
	}
	return "", authz.KeyInfo{}, tokenUnknown
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="ryvex"`)
	writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "missing or invalid bearer token (expected ryk_ API key)")
}

// deriveScope maps a request onto the org/project it targets. The
// segment grammar mirrors routeV1. POST /v1/resources peeks at the
// JSON body for org/project and reinjects a replacement reader so the
// handler can decode the body normally. handled=true means a response
// was already written (413 for an oversized body, issue #38) and the
// request must not proceed.
func deriveScope(w http.ResponseWriter, r *http.Request) (scope requestScope, handled bool) {
	p := r.URL.Path
	if p == "/" || p == "/v1" || p == "/v1/" {
		return requestScope{pass: true}, false
	}
	trimmed := strings.Trim(strings.TrimPrefix(p, "/v1"), "/")
	seg := strings.Split(trimmed, "/")
	if seg[0] == "keys" {
		// Key management self-enforces admin inside the handlers.
		return requestScope{pass: true}, false
	}
	switch {
	case seg[0] == "resources" && len(seg) == 1:
		if r.Method == http.MethodPost {
			org, project, ok := peekBodyScope(w, r)
			if !ok {
				return requestScope{}, true
			}
			return requestScope{org: org, project: project, write: true}, false
		}
		org := r.URL.Query().Get("org")
		if org == "" {
			// Unfiltered cross-org listing is admin terrain.
			return requestScope{adminOnly: true}, false
		}
		return requestScope{org: org, project: r.URL.Query().Get("project")}, false
	case seg[0] == "resources" && len(seg) == 2:
		// Opaque-ID address: scope cannot be derived from the path.
		return requestScope{adminOnly: true}, false
	case len(seg) == 2 && (seg[1] == "events" || seg[1] == "audit"):
		return requestScope{org: seg[0]}, false
	case len(seg) == 3 && seg[1] == "reconcile":
		return requestScope{org: seg[0], write: true}, false
	case len(seg) == 4:
		return requestScope{org: seg[0], project: seg[1]}, false
	case len(seg) == 5:
		return requestScope{org: seg[0], project: seg[1], write: r.Method != http.MethodGet}, false
	default:
		// Unknown /v1 route: conservative — admins only.
		return requestScope{adminOnly: true}, false
	}
}

// peekBodyScope reads (and reinjects) the request body to extract the
// org/project a POST /v1/resources write targets. Bodies over the 1
// MiB cap are rejected here with a dedicated 413 instead of surfacing
// downstream as a truncated-JSON 400 (issue #38); ok=false means the
// response was written.
func peekBodyScope(w http.ResponseWriter, r *http.Request) (org, project string, ok bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err == nil && len(body) > maxBodyBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
			"request body exceeds the 1 MiB limit")
		return "", "", false
	}
	if err == nil {
		var probe struct {
			Org     string `json:"org"`
			Project string `json:"project"`
		}
		if json.Unmarshal(body, &probe) == nil {
			org, project = probe.Org, probe.Project
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return org, project, true
}
