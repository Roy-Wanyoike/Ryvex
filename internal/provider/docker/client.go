package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
)

// Client is a hand-rolled Docker Engine API client: HTTP over the
// engine's unix socket via a custom-dialer http.Transport (stdlib
// only, issue #80). It speaks the small subset of the Engine API the
// reference actuator needs:
//
//	GET    /_ping
//	GET    /containers/{name}/json
//	POST   /containers/create?name={name}
//	POST   /containers/{id}/start
//	POST   /containers/{id}/stop?t={secs}
//	DELETE /containers/{id}?force=true
//
// The URL host is a placeholder ("docker") — the dialer ignores it and
// always connects to the configured socket. Transport errors classify
// as Unavailable; decode errors as Permanent (a bug or a lying peer,
// both hopeless to retry); HTTP statuses via ClassifyStatus.
type Client struct {
	http   *http.Client
	socket string
}

// NewClient returns a client for the Engine socket at socketPath.
func NewClient(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       4,
		IdleConnTimeout:    time.Minute,
	}
	return &Client{
		http:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
		socket: socketPath,
	}
}

// Socket reports the socket path the client dials (for boot logs).
func (c *Client) Socket() string { return c.socket }

// ErrConflict marks a create that raced with an existing object (HTTP
// 409): errors.Is-able so Apply can fall back to adopting the object
// (create-after-crash idempotency).
var ErrConflict = errors.New("docker: name already in use")

// ContainerConfig is the subset of the Engine's container config the
// actuator sets on create.
type ContainerConfig struct {
	Image  string            `json:"Image"`
	Env    []string          `json:"Env,omitempty"`
	Labels map[string]string `json:"Labels,omitempty"`
}

// Container is the subset of the Engine inspect response the actuator
// decodes for drift comparison.
type Container struct {
	Id     string           `json:"Id"`
	Name   string           `json:"Name"`
	Config *ContainerConfig `json:"Config"`
	State  *ContainerState  `json:"State"`
}

// ContainerState is the lifecycle slice of the inspect response.
type ContainerState struct {
	Status    string `json:"Status"`
	Running   bool   `json:"Running"`
	Dead      bool   `json:"Dead"`
	OOMKilled bool   `json:"OOMKilled"`
}

// createResponse is the Engine's container creation reply.
type createResponse struct {
	Id       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

// apiError is the Engine's standard error envelope: {"message": "..."}.
type apiError struct {
	Message string `json:"message"`
}

// Ping verifies the engine answers GET /_ping. Used at boot so an
// explicitly requested actuator fails the daemon loudly instead of
// limping (same posture as --bus=nats on a failed dial).
func (c *Client) Ping(ctx context.Context) error {
	code, raw, err := c.do(ctx, "ping", http.MethodGet, "/_ping", nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return statusError("ping", code, raw)
	}
	return nil
}

// InspectContainer fetches one container by name or ID. Absence
// (HTTP 404) is not an error: it returns (nil, false, nil) so the
// reconciler can plan a create.
func (c *Client) InspectContainer(ctx context.Context, nameOrID string) (*Container, bool, error) {
	code, raw, err := c.do(ctx, "inspect", http.MethodGet, "/containers/"+url.PathEscape(nameOrID)+"/json", nil)
	if err != nil {
		return nil, false, err
	}
	switch {
	case code == http.StatusNotFound:
		return nil, false, nil
	case code/100 == 2:
		var ctr Container
		if err := json.Unmarshal(raw, &ctr); err != nil {
			return nil, false, provider.E(provider.Permanent, "inspect", fmt.Errorf("decode inspect response: %w", err))
		}
		return &ctr, true, nil
	default:
		return nil, false, statusError("inspect", code, raw)
	}
}

// CreateContainer creates a container with the given name and config.
// HTTP 409 wraps ErrConflict (classified Transient — the reconcile
// loop or the ensure fallback resolves it).
func (c *Client) CreateContainer(ctx context.Context, name string, cfg ContainerConfig) (string, error) {
	code, raw, err := c.do(ctx, "create", http.MethodPost,
		"/containers/create?name="+url.QueryEscape(name), cfg)
	if err != nil {
		return "", err
	}
	if code == http.StatusCreated {
		var cr createResponse
		if err := json.Unmarshal(raw, &cr); err != nil {
			return "", provider.E(provider.Permanent, "create", fmt.Errorf("decode create response: %w", err))
		}
		if cr.Id == "" {
			return "", provider.E(provider.Permanent, "create", errors.New("engine returned an empty container id"))
		}
		return cr.Id, nil
	}
	if code == http.StatusConflict {
		var ae apiError
		_ = json.Unmarshal(raw, &ae)
		return "", provider.E(provider.Transient, "create", fmt.Errorf("%w: %s", ErrConflict, ae.Message))
	}
	return "", statusError("create", code, raw)
}

// StartContainer starts a created container. 304 (already started) is
// success — retries must be harmless.
func (c *Client) StartContainer(ctx context.Context, nameOrID string) error {
	code, raw, err := c.do(ctx, "start", http.MethodPost, "/containers/"+url.PathEscape(nameOrID)+"/start", nil)
	if err != nil {
		return err
	}
	if code == http.StatusNoContent || code == http.StatusNotModified {
		return nil
	}
	return statusError("start", code, raw)
}

// StopContainer stops a running container with a graceful timeout.
// 304 (already stopped) and 404 (already gone) are success.
func (c *Client) StopContainer(ctx context.Context, nameOrID string, timeoutSecs int) error {
	code, raw, err := c.do(ctx, "stop", http.MethodPost,
		fmt.Sprintf("/containers/%s/stop?t=%d", url.PathEscape(nameOrID), timeoutSecs), nil)
	if err != nil {
		return err
	}
	switch code {
	case http.StatusNoContent, http.StatusNotModified, http.StatusNotFound:
		return nil
	default:
		return statusError("stop", code, raw)
	}
}

// RemoveContainer force-removes a container (anonymous volumes are
// kept: v is deliberately false). 404 is success.
func (c *Client) RemoveContainer(ctx context.Context, nameOrID string) error {
	code, raw, err := c.do(ctx, "remove", http.MethodDelete,
		"/containers/"+url.PathEscape(nameOrID)+"?force=true", nil)
	if err != nil {
		return err
	}
	if code == http.StatusNoContent || code == http.StatusNotFound {
		return nil
	}
	return statusError("remove", code, raw)
}

// do performs one API round trip and returns the status code plus the
// (bounded) response body.
func (c *Client) do(ctx context.Context, op, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, provider.E(provider.Permanent, op, fmt.Errorf("encode request: %w", err))
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, rd)
	if err != nil {
		return 0, nil, provider.E(provider.Permanent, op, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, provider.E(provider.Unavailable, op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, provider.E(provider.Transient, op, fmt.Errorf("read response: %w", err))
	}
	return resp.StatusCode, raw, nil
}

// statusError builds the canonical classified error for a non-2xx
// Engine response, unwrapping its {"message": ...} envelope.
func statusError(op string, code int, raw []byte) error {
	var ae apiError
	_ = json.Unmarshal(raw, &ae)
	if ae.Message == "" {
		return provider.E(ClassifyStatus(code), op, fmt.Errorf("engine returned http %d", code))
	}
	return provider.E(ClassifyStatus(code), op, errors.New(ae.Message))
}
