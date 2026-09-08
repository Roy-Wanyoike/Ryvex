package api

import (
	"io"
	"log/slog"
)

// discardLogger returns a logger that writes nowhere (used in tests).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
