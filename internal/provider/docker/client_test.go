package docker

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
)

// fakeEngine is a minimal Docker Engine API fake served over a real
// unix socket (the transport the client is built for). It records the
// call order so actuator flows can assert exact sequences.
type fakeEngine struct {
	mu    sync.Mutex
	calls []string
	ctr   *Container // nil = no container exists
	seq   int
	cfg   ContainerConfig // last create body
}

func (e *fakeEngine) logf(call string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, call)
}

func (e *fakeEngine) snapshotCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

func (e *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_ping" && r.Method == http.MethodGet:
		w.WriteHeader(http.StatusOK)

	case r.URL.Path == "/containers/create" && r.Method == http.MethodPost:
		name := r.URL.Query().Get("name")
		e.mu.Lock()
		if e.ctr != nil {
			e.mu.Unlock()
			e.logf("create:" + name) // record the attempt too: adopt flows key off it
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Conflict. The container name is already in use"})
			return
		}
		e.seq++
		id := strings.Repeat("d", 12) + "000" + string(rune('a'+e.seq%26))
		_ = json.NewDecoder(r.Body).Decode(&e.cfg)
		e.ctr = &Container{
			Id:     id,
			Name:   "/" + name,
			Config: &ContainerConfig{Image: e.cfg.Image, Env: e.cfg.Env, Labels: e.cfg.Labels},
			State:  &ContainerState{Status: "created"},
		}
		e.mu.Unlock()
		e.logf("create:" + name)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": id, "Warnings": nil})

	case strings.HasSuffix(r.URL.Path, "/json") && r.Method == http.MethodGet:
		e.logf("inspect")
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.ctr == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such container"})
			return
		}
		_ = json.NewEncoder(w).Encode(e.ctr)

	case strings.HasSuffix(r.URL.Path, "/start") && r.Method == http.MethodPost:
		e.mu.Lock()
		if e.ctr == nil {
			e.mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such container"})
			return
		}
		e.ctr.State = &ContainerState{Status: "running", Running: true}
		e.mu.Unlock()
		e.logf("start")
		w.WriteHeader(http.StatusNoContent)

	case strings.HasSuffix(r.URL.Path, "/stop") && r.Method == http.MethodPost:
		e.mu.Lock()
		if e.ctr == nil {
			e.mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such container"})
			return
		}
		e.ctr.State = &ContainerState{Status: "exited"}
		e.mu.Unlock()
		e.logf("stop")
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete:
		e.mu.Lock()
		absent := e.ctr == nil
		e.ctr = nil
		e.mu.Unlock()
		e.logf("remove")
		if absent {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such container"})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
	}
}

// serveOnNewSocket runs h on a fresh unix socket and returns the path.
func serveOnNewSocket(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ryvex-docker-test")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "engine.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

func newFakeEngine(t *testing.T) (string, *fakeEngine) {
	t.Helper()
	e := &fakeEngine{}
	return serveOnNewSocket(t, e), e
}

func TestPingOK(t *testing.T) {
	socket, _ := newFakeEngine(t)
	if err := NewClient(socket).Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestTransportFailureClassifiesUnavailable(t *testing.T) {
	// A socket that does not exist: the dial error must surface as
	// Unavailable (operational, retryable), not Permanent.
	c := NewClient(filepath.Join(t.TempDir(), "missing.sock"))
	err := c.Ping(t.Context())
	if err == nil {
		t.Fatal("Ping on a dead socket must fail")
	}
	if got := provider.ClassOf(err); got != provider.Unavailable {
		t.Fatalf("class = %v (%v), want unavailable", got, err)
	}
}

func TestPingNon200ClassifiesByStatus(t *testing.T) {
	// A 503 engine with the standard error envelope: Transient (the
	// operation may succeed later), message preserved.
	socket := serveOnNewSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "engine on fire"})
	}))
	err := NewClient(socket).Ping(t.Context())
	if err == nil {
		t.Fatal("Ping on a 503 engine must fail")
	}
	if got := provider.ClassOf(err); got != provider.Transient {
		t.Fatalf("class = %v (%v), want transient", got, err)
	}
	if !strings.Contains(err.Error(), "engine on fire") {
		t.Fatalf("error lost the engine's message envelope: %v", err)
	}
}

func TestInspectContainerAbsenceAndPresence(t *testing.T) {
	socket, e := newFakeEngine(t)
	c := NewClient(socket)
	ctx := t.Context()

	// Absent: not an error, exists=false (the SPI's 404 contract).
	ctr, exists, err := c.InspectContainer(ctx, "nope")
	if err != nil || exists || ctr != nil {
		t.Fatalf("absent inspect = (%v, %v, %v), want (nil, false, nil)", ctr, exists, err)
	}

	// Present: decodes the subset the actuator needs.
	e.mu.Lock()
	e.ctr = &Container{
		Id:     "deadbeefdeadbeef",
		Name:   "/ryvex-x",
		Config: &ContainerConfig{Image: "demo:1", Env: []string{"A=1"}},
		State:  &ContainerState{Status: "running", Running: true},
	}
	e.mu.Unlock()
	ctr, exists, err = c.InspectContainer(ctx, "ryvex-x")
	if err != nil || !exists {
		t.Fatalf("inspect = (%v, %v, %v)", ctr, exists, err)
	}
	if ctr.Id != "deadbeefdeadbeef" || ctr.Config.Image != "demo:1" || !ctr.State.Running {
		t.Fatalf("decoded container wrong: %+v", ctr)
	}
}

func TestCreateContainerConflictWrapsSentinel(t *testing.T) {
	socket, e := newFakeEngine(t)
	c := NewClient(socket)

	e.mu.Lock()
	e.ctr = &Container{Id: "already-here", State: &ContainerState{Status: "created"}}
	e.mu.Unlock()

	_, err := c.CreateContainer(t.Context(), "ryvex-x", ContainerConfig{Image: "demo:1"})
	if err == nil {
		t.Fatal("create over an existing name must fail")
	}
	// The actuator's adopt fallback keys off errors.Is(ErrConflict);
	// the client wraps the sentinel and classifies Transient (a race
	// the reconcile loop can resolve).
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("409 must wrap ErrConflict: %v", err)
	}
	if got := provider.ClassOf(err); got != provider.Transient {
		t.Fatalf("class = %v, want transient", got)
	}
}

func TestStartStopRemoveStatusHandling(t *testing.T) {
	socket, _ := newFakeEngine(t)
	c := NewClient(socket)
	ctx := t.Context()

	// Start on an absent container is a real 404 failure (Permanent —
	// only stop/remove get the already-gone pass).
	err := c.StartContainer(ctx, "missing")
	if err == nil || provider.ClassOf(err) != provider.Permanent {
		t.Fatalf("404 start class = %v (%v), want permanent", provider.ClassOf(err), err)
	}
	// Stop/remove treat 404 as success (already gone).
	if err := c.StopContainer(ctx, "missing", 10); err != nil {
		t.Fatalf("stop on absent container must be success, got %v", err)
	}
	if err := c.RemoveContainer(ctx, "missing"); err != nil {
		t.Fatalf("remove on absent container must be success, got %v", err)
	}
}
