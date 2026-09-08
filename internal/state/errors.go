// Package state defines the Ryvex resource model and the in-memory
// state store that backs the control plane API.
package state

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the store. The API layer maps these to
// HTTP status codes.
var (
	// ErrNotFound is returned when a resource (or audit entry) does not exist.
	ErrNotFound = errors.New("resource not found")

	// ErrAlreadyExists is returned when creating a resource whose logical
	// address (org/project/env/kind/name) is already taken.
	ErrAlreadyExists = errors.New("resource already exists")

	// ErrConflict is returned when an update fails its compare-and-swap
	// check, i.e. the caller's ExpectedGeneration is stale.
	ErrConflict = errors.New("generation conflict")

	// ErrValidation is returned when a resource fails schema validation.
	ErrValidation = errors.New("validation failed")

	// ErrBadRequest is returned for malformed cursors or query values.
	ErrBadRequest = errors.New("bad request")
)

// ValidationError carries a human-readable field-level message.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Message)
}

// Unwrap makes errors.Is(err, state.ErrValidation) work.
func (e *ValidationError) Unwrap() error { return ErrValidation }
