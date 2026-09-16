//go:build !docker

package main

import (
	"log/slog"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
)

// dockerActuators is the !docker half of the build-tag seam (issue
// #80, docs/adr/0002-provider-spi.md): binaries built without
// `-tags docker` carry no actuator at all. An explicit
// --enable-docker-actuator here is an operator mistake worth shouting
// about, but not a crash: the daemon warns loudly and converges
// status-only — the honest-degradation convention (ADR-0002
// requirement 7, same family as the store/bus/boot honesty rules).
func dockerActuators(enabled bool, _ string, log *slog.Logger) ([]provider.Actuator, error) {
	if enabled {
		log.Warn("Docker actuator requested but this binary was built without '-tags docker': " +
			"continuing with status-only convergence (rebuild with -tags docker to actuate)")
	}
	return nil, nil
}
