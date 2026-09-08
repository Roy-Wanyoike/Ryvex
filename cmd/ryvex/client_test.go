package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(base, token string) *Client {
	return &Client{Base: base, Token: token}
}

func TestDoSuccess(t *testing.T) {
	var gotAuth, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resources/r-1" {
			t.Errorf("path = %q, want /v1/resources/r-1", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		_, _ = io.WriteString(w, `{"id":"r-1"}`)
	}))
	defer srv.Close()

	raw, err := testClient(srv.URL, "ryk_test").Do(http.MethodGet, "/v1/resources/r-1", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(raw) != `{"id":"r-1"}` {
		t.Fatalf("body = %q", raw)
	}
	if gotAuth != "Bearer ryk_test" {
		t.Fatalf("Authorization = %q, want Bearer ryk_test", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", gotAccept)
	}
}

func TestDoPostSetsContentType(t *testing.T) {
	var gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	payload := []byte(`{"kind":"Application"}`)
	if _, err := testClient(srv.URL, "ryk_test").Do(http.MethodPost, "/v1/resources", payload); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotType)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body = %q, want %q", gotBody, payload)
	}
}

func TestDoOmitsAuthHeaderWithoutToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL, "").Do(http.MethodGet, "/healthz", nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want absent", gotAuth)
	}
}

func TestDoTrimsTrailingSlashFromBase(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL+"/", "").Do(http.MethodGet, "/healthz", nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotPath != "/healthz" {
		t.Fatalf("path = %q, want /healthz (double slash means base was not trimmed)", gotPath)
	}
}

func TestErrorEnvelope404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"resource not found","request_id":"e3b0c44298fc","details":[]}}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, "ryk_test").Do(http.MethodGet, "/v1/resources/r-missing", nil)
	var ae *ApiError
	if !errors.As(err, &ae) {
		t.Fatalf("want *ApiError, got %T: %v", err, err)
	}
	if ae.Status != 404 || ae.Code != "not_found" || ae.Message != "resource not found" || ae.RequestID != "e3b0c44298fc" {
		t.Fatalf("decoded = %+v", ae)
	}
	want := "ryvex: resource not found (code=not_found, request_id=e3b0c44298fc)"
	if ae.Error() != want {
		t.Fatalf("Error() = %q, want %q", ae.Error(), want)
	}
}

func TestErrorEnvelope409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"conflict","message":"generation conflict: resource was modified concurrently","request_id":"abc123","details":[]}}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, "ryk_test").Do(http.MethodPost, "/v1/resources", []byte(`{}`))
	var ae *ApiError
	if !errors.As(err, &ae) {
		t.Fatalf("want *ApiError, got %T: %v", err, err)
	}
	if ae.Status != 409 || ae.Code != "conflict" || ae.RequestID != "abc123" {
		t.Fatalf("decoded = %+v", ae)
	}
	if !strings.HasPrefix(ae.Message, "generation conflict") {
		t.Fatalf("message = %q", ae.Message)
	}
	want := "ryvex: generation conflict: resource was modified concurrently (code=conflict, request_id=abc123)"
	if ae.Error() != want {
		t.Fatalf("Error() = %q, want %q", ae.Error(), want)
	}
}

func TestErrorEnvelopeWithoutRequestID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"conflict","message":"boom"}}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, "").Do(http.MethodGet, "/x", nil)
	var ae *ApiError
	if !errors.As(err, &ae) {
		t.Fatalf("want *ApiError, got %T", err)
	}
	if want := "ryvex: boom (code=conflict)"; ae.Error() != want {
		t.Fatalf("Error() = %q, want %q", ae.Error(), want)
	}
}

func TestNonEnvelopeErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>bad gateway</html>")
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, "").Do(http.MethodGet, "/v1", nil)
	var ae *ApiError
	if !errors.As(err, &ae) {
		t.Fatalf("want *ApiError, got %T", err)
	}
	if ae.Code != "unexpected_response" || ae.Status != 502 {
		t.Fatalf("decoded = %+v", ae)
	}
	if !strings.Contains(ae.Message, "HTTP 502") {
		t.Fatalf("message = %q, want HTTP 502 prefix", ae.Message)
	}
}

func TestTransportFailureIsNotApiError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing is listening now

	_, err := testClient(srv.URL, "").Do(http.MethodGet, "/healthz", nil)
	if err == nil {
		t.Fatal("want transport error, got nil")
	}
	var ae *ApiError
	if errors.As(err, &ae) {
		t.Fatalf("transport failure must not decode into ApiError, got %+v", ae)
	}
}
