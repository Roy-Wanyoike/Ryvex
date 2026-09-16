// Package api implements the Ryvex REST control plane (the /v1 face).
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Error envelope shape (frozen contract, see docs/api-contracts.md):
//
//	{"error": {"code": "...", "message": "...", "request_id": "...", "details": []}}
type errorBody struct {
	Error errDetail `json:"error"`
}

type errDetail struct {
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	RequestID string   `json:"request_id,omitempty"`
	Details   []string `json:"details"`
}

// API error codes (stable wire values).
const (
	CodeNotFound         = "not_found"
	CodeAlreadyExists    = "already_exists"
	CodeConflict         = "conflict"
	CodeValidation       = "validation_failed"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden" // RBAC denial (issue #16)
	CodeMethodNotAllowed = "method_not_allowed"
	CodeBadRequest       = "bad_request"
	CodePayloadTooLarge  = "payload_too_large" // 413 (issue #38)
	CodeInternal         = "internal_error"
)

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	rid := RequestIDFrom(r.Context())
	details := []string{}
	if details == nil {
		details = make([]string, 0)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errDetail{
		Code: code, Message: msg, RequestID: rid, Details: details,
	}})
}

// stateStatus maps store sentinel errors onto HTTP responses. Mapping
// uses errors.Is (#84) so wrapped errors — fmt.Errorf("...: %w", err)
// chains added by future callers — still land on the right status
// instead of falling through to a misleading 500.
func stateStatus(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case isValidation(err):
		writeError(w, r, http.StatusBadRequest, CodeValidation, err.Error())
	case errors.Is(err, state.ErrNotFound):
		writeError(w, r, http.StatusNotFound, CodeNotFound, "resource not found")
	case errors.Is(err, state.ErrAlreadyExists):
		writeError(w, r, http.StatusConflict, CodeAlreadyExists, "resource already exists at this address")
	case errors.Is(err, state.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "generation conflict: resource was modified concurrently")
	case errors.Is(err, state.ErrBadRequest):
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, err.Error())
	default:
		writeError(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func isValidation(err error) bool {
	var ve *state.ValidationError
	if ok := asValidation(err, &ve); ok {
		return true
	}
	return errors.Is(err, state.ErrValidation)
}

// asValidation unwraps the error chain looking for a
// *state.ValidationError (errors.As, #84), so validation errors
// wrapped by intermediate layers are still recognized and their
// field-level message surfaced.
func asValidation(err error, target **state.ValidationError) bool {
	return errors.As(err, target)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
