//go:build docker

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/provider/docker"
)

// dockerActuators wires the reference Docker actuator (issue #80,
// docs/adr/0002-provider-spi.md). This build-tag half runs in binaries
// compiled with `-tags docker`: an explicitly enabled actuator must
// reach its engine at boot, or the daemon refuses to start — a control
// plane that claims to actuate while unable to reach the engine is the
// one failure mode worse than a crash (same posture as --bus=nats on a
// failed dial). Without --enable-docker-actuator the daemon behaves
// exactly as a status-only deployment.
func dockerActuators(enabled bool, socket string, log *slog.Logger) ([]provider.Actuator, error) {
	if !enabled {
		return nil, nil
	}
	c := docker.NewClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		return nil, fmt.Errorf("docker actuator enabled but the engine is unreachable at %s: %w (refusing to start; unset --enable-docker-actuator to run status-only)", socket, err)
	}
	log.Info("docker actuator enabled", "socket", socket)
	return []provider.Actuator{docker.NewActuator(c)}, nil
}
