package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a thin HTTP wrapper around the Ryvex /v1 face: bearer
// auth, JSON bodies, and error-envelope decoding per the frozen
// contract in docs/api-contracts.md.
type Client struct {
	// Base is the control plane base URL, e.g. http://127.0.0.1:8080.
	Base string
	// Token is the bearer API key; empty omits the header entirely.
	Token string
	// HTTP is the transport; nil installs a client with a timeout.
	HTTP *http.Client
}

// requestTimeout bounds every API call; a control plane that does not
// answer within 15s is down for operator purposes.
const requestTimeout = 15 * time.Second

// ApiError is a decoded error envelope from the control plane. Its
// Error method renders the operator-facing form:
//
//	ryvex: <message> (code=<code>, request_id=<rid>)
type ApiError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *ApiError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("ryvex: %s (code=%s, request_id=%s)", e.Message, e.Code, e.RequestID)
	}
	return fmt.Sprintf("ryvex: %s (code=%s)", e.Message, e.Code)
}

// errorEnvelope mirrors the frozen wire shape:
//
//	{"error": {"code": "...", "message": "...", "request_id": "...", "details": []}}
type errorEnvelope struct {
	Error struct {
		Code      string   `json:"code"`
		Message   string   `json:"message"`
		RequestID string   `json:"request_id"`
		Details   []string `json:"details"`
	} `json:"error"`
}

// Do performs one API call and returns the raw response body. Non-2xx
// responses are decoded into *ApiError; transport failures surface as
// the underlying net/http error.
func (c *Client) Do(method, path string, body []byte) ([]byte, error) {
	endpoint := strings.TrimRight(c.Base, "/") + path
	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, decodeApiError(resp.StatusCode, raw)
	}
	return raw, nil
}

// decodeApiError parses the frozen error envelope; a non-envelope
// body (proxy error page, truncated reply) still yields a usable
// ApiError instead of a bare status code.
func decodeApiError(status int, raw []byte) error {
	var env errorEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Error.Code != "" {
		return &ApiError{
			Status:    status,
			Code:      env.Error.Code,
			Message:   env.Error.Message,
			RequestID: env.Error.RequestID,
		}
	}
	return &ApiError{
		Status:  status,
		Code:    "unexpected_response",
		Message: fmt.Sprintf("HTTP %d: %.256s", status, raw),
	}
}

// client builds a Client from the parsed global flags.
func (g globals) client() *Client {
	return &Client{Base: g.api, Token: g.token}
}

// querySuffix encodes query parameters, returning "" when empty.
func querySuffix(q url.Values) string {
	if enc := q.Encode(); enc != "" {
		return "?" + enc
	}
	return ""
}

// ---- client-side views of API documents ----
//
// Only the fields the CLI renders are decoded; unknown fields are
// tolerated per the API contract.

// resourceDoc is the control plane resource document.
type resourceDoc struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Org        string `json:"org"`
	Project    string `json:"project"`
	Env        string `json:"env"`
	Name       string `json:"name"`
	Generation int64  `json:"generation"`
	Status     struct {
		Phase   string `json:"phase"`
		Message string `json:"message"`
	} `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// address is the logical scope address of the resource.
func (r resourceDoc) address() string {
	return strings.Join([]string{r.Org, r.Project, r.Env, r.Kind, r.Name}, "/")
}

// eventsPage is the wire shape of GET /v1/{org}/events.
type eventsPage struct {
	Events []eventDoc `json:"events"`
	Count  int        `json:"count"`
}

// eventDoc carries the fields the events table renders.
type eventDoc struct {
	Subject string    `json:"subject"`
	Kind    string    `json:"kind"`
	Name    string    `json:"name"`
	Time    time.Time `json:"time"`
}

// auditPage is the wire shape of GET /v1/{org}/audit.
type auditPage struct {
	Entries []auditDoc `json:"entries"`
	Count   int        `json:"count"`
}

// auditDoc carries the fields the audit table renders.
type auditDoc struct {
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	LogicalKey string    `json:"logical_key"`
	Time       time.Time `json:"time"`
}

// reconcileDoc is the 202 response of POST /v1/{org}/reconcile/{id}.
type reconcileDoc struct {
	Status     string `json:"status"`
	ResourceID string `json:"resource_id"`
	Reason     string `json:"reason"`
}

// healthDoc is the /healthz document.
type healthDoc struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version"`
	Resources int    `json:"resources"`
}
