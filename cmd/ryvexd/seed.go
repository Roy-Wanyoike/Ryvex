package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// seedDemoData loads a small, realistic demo dataset so a fresh
// daemon has something interesting to serve: one org, one project,
// two environments, and the workloads that run in them.
func seedDemoData(ctx context.Context, store state.Backend, log *slog.Logger) (int, error) {
	spec := func(kv map[string]any) map[string]any { return kv }
	labels := func(kv map[string]string) map[string]string { return kv }

	resources := []state.Resource{
		// --- scope: acme / core ---
		{Kind: state.KindProject, Org: "acme", Project: "core", Env: "prod", Name: "core",
			Labels: labels(map[string]string{"managed-by": "ryvex", "tier": "platform"}),
			Spec:   spec(map[string]any{"description": "Acme core commerce platform", "owner": "platform-team"})},

		{Kind: state.KindEnvironment, Org: "acme", Project: "core", Env: "prod", Name: "prod",
			Labels: labels(map[string]string{"managed-by": "ryvex", "tier": "production"}),
			Spec:   spec(map[string]any{"region": "eu-west-1", "protection": "full"})},
		{Kind: state.KindEnvironment, Org: "acme", Project: "core", Env: "staging", Name: "staging",
			Labels: labels(map[string]string{"managed-by": "ryvex", "tier": "staging"}),
			Spec:   spec(map[string]any{"region": "eu-west-1", "protection": "none"})},

		// --- applications ---
		{Kind: state.KindApplication, Org: "acme", Project: "core", Env: "prod", Name: "checkout",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "payments"}),
			Spec:   spec(map[string]any{"image": "registry.acme.io/checkout:1.42.0", "replicas": 4, "port": 8080})},
		{Kind: state.KindApplication, Org: "acme", Project: "core", Env: "prod", Name: "web",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "storefront"}),
			Spec:   spec(map[string]any{"image": "registry.acme.io/web:2.7.3", "replicas": 6, "port": 3000})},

		// --- deployment history ---
		{Kind: state.KindDeployment, Org: "acme", Project: "core", Env: "prod", Name: "checkout-1-42-0",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "payments"}),
			Spec:   spec(map[string]any{"application": "checkout", "image": "registry.acme.io/checkout:1.42.0", "strategy": "rolling", "commit": "9f3e2a1"})},

		// --- infrastructure ---
		{Kind: state.KindCluster, Org: "acme", Project: "core", Env: "prod", Name: "prod-eu1",
			Labels: labels(map[string]string{"managed-by": "ryvex", "region": "eu-west-1"}),
			Spec:   spec(map[string]any{"provider": "aws", "version": "1.30", "nodes": 2, "cpus": 32})},
		{Kind: state.KindNode, Org: "acme", Project: "core", Env: "prod", Name: "prod-eu1-a",
			Labels: labels(map[string]string{"managed-by": "ryvex", "instance": "m6i.2xlarge"}),
			Spec:   spec(map[string]any{"cluster": "prod-eu1", "capacity_gb": 512, "status": "joined"})},
		{Kind: state.KindNode, Org: "acme", Project: "core", Env: "prod", Name: "prod-eu1-b",
			Labels: labels(map[string]string{"managed-by": "ryvex", "instance": "m6i.2xlarge"}),
			Spec:   spec(map[string]any{"cluster": "prod-eu1", "capacity_gb": 512, "status": "joined"})},

		// --- data services ---
		{Kind: state.KindDatabase, Org: "acme", Project: "core", Env: "prod", Name: "orders-postgres",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "payments"}),
			Spec:   spec(map[string]any{"engine": "postgres", "version": "16", "size": "db.m6g.large", "ha": true})},
		{Kind: state.KindCache, Org: "acme", Project: "core", Env: "prod", Name: "sessions-redis",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "storefront"}),
			Spec:   spec(map[string]any{"engine": "redis", "version": "7.2", "size": "cache.m6g.large", "eviction": "allkeys-lru"})},
		{Kind: state.KindBucket, Org: "acme", Project: "core", Env: "prod", Name: "invoice-archive",
			Labels: labels(map[string]string{"managed-by": "ryvex", "team": "billing"}),
			Spec:   spec(map[string]any{"provider": "aws", "versioning": true, "encryption": "aws:kms"})},

		// --- governance ---
		{Kind: state.KindPolicy, Org: "acme", Project: "core", Env: "prod", Name: "require-approval-prod",
			Labels: labels(map[string]string{"managed-by": "ryvex", "governance": "change-control"}),
			Spec:   spec(map[string]any{"applies_to": []string{"Deployment", "Database"}, "min_approvers": 2, "window": "business-hours"})},
		{Kind: state.KindPolicy, Org: "acme", Project: "core", Env: "prod", Name: "deny-public-buckets",
			Labels: labels(map[string]string{"managed-by": "ryvex", "governance": "security"}),
			Spec:   spec(map[string]any{"applies_to": []string{"Bucket"}, "deny": []string{"public_read"}})},

		{Kind: state.KindSecret, Org: "acme", Project: "core", Env: "prod", Name: "stripe-api-key",
			Labels: labels(map[string]string{"managed-by": "ryvex", "rotation": "30d"}),
			Spec:   spec(map[string]any{"provider": "vault", "keys": []string{"secret_key", "webhook_secret"}})},
	}

	count := 0
	for i := range resources {
		r := resources[i]
		if _, err := store.CreateResource(&r, state.WriteOptions{Actor: "ryvexd-seed", Reason: "bootstrap"}); err != nil {
			if err == state.ErrAlreadyExists {
				continue // idempotent restart
			}
			return count, fmt.Errorf("seed %s: %w", r.LogicalKey(), err)
		}
		count++
	}
	log.Debug("seed complete", "created", count, "total_defined", len(resources))
	return count, nil
}
