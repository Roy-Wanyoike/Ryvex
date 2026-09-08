/**
 * Live integration test against a real ryvexd daemon.
 *
 * SKIPPED unless RYVEX_INTEGRATION === "1". When enabled it boots
 * against the daemon at RYVEX_TEST_API with the bearer token from
 * RYVEX_TEST_TOKEN and walks the full resource lifecycle:
 *
 *   health → index → create → get → list → put (CAS) → stale-put
 *   conflict (409) → reconcile → events/audit → delete → 404
 *
 * Local run:
 *
 *   go build -o /tmp/ryvexd ./cmd/ryvexd
 *   /tmp/ryvexd serve --http 127.0.0.1:18201 --dev-auth --seed --log-level error &
 *   RYVEX_INTEGRATION=1 RYVEX_TEST_API=http://127.0.0.1:18201 \
 *     RYVEX_TEST_TOKEN=ryk_ts_agent bun test test/integration.test.ts
 */
import { describe, expect, test } from "bun:test";
import { Ryvex, RyvexError } from "../src/index.js";

const enabled = process.env.RYVEX_INTEGRATION === "1";
const baseUrl = process.env.RYVEX_TEST_API ?? "";
const token = process.env.RYVEX_TEST_TOKEN ?? "";

describe.skipIf(!enabled)("Ryvex client · live integration", () => {
  test("full lifecycle: create → get → list → CAS put → conflict → delete → 404", async () => {
    const client = new Ryvex({ baseUrl, token });
    // A dedicated org + timestamped name keeps the run isolated from
    // seed data and from concurrent runs against the same daemon.
    const org = "sdkint";
    const project = "it";
    const env = "prod";
    const name = `ts-sdk-${Date.now().toString(36)}`;

    // 0. service face
    const health = await client.health();
    expect(health.status).toBe("ok");
    expect(health.service).toBe("ryvexd");

    const index = await client.index();
    expect(index.endpoints.length).toBeGreaterThan(0);

    // 1. create (201)
    const created = await client.createResource({
      kind: "Application",
      org,
      project,
      env,
      name,
      labels: { team: "sdk-e2e" },
      spec: { image: "registry.ryvex.dev/checkout:1.0.0", replicas: 2 },
    });
    expect(created.id).toMatch(/^r-/);
    expect(created.generation).toBe(1);
    expect(created.status.phase).toBe("Pending");
    const id = created.id;

    try {
      // 2. get by handle
      const got = await client.getResource(id);
      expect(got.name).toBe(name);
      expect(got.org).toBe(org);

      // 3. get by logical address
      const inScope = await client.getInScope(org, project, env, "applications", name);
      expect(inScope.id).toBe(id);

      // 4. list (filtered page + listAll)
      const page = await client.listResources({ org, kind: "applications" });
      expect(page.items.some((r) => r.id === id)).toBeTrue();
      const all: string[] = [];
      for await (const r of client.listAll({ org })) {
        all.push(r.id);
      }
      expect(all).toContain(id);

      // 5. upsert with CAS (generation 1 → 2)
      const updated = await client.putInScope(org, project, env, "applications", name, {
        generation: created.generation,
        spec: { image: "registry.ryvex.dev/checkout:1.1.0", replicas: 3 },
      });
      expect(updated.generation).toBe(2);
      expect(updated.spec).toEqual({ image: "registry.ryvex.dev/checkout:1.1.0", replicas: 3 });

      // 6. stale CAS write → 409 conflict
      let conflict: unknown;
      try {
        await client.putInScope(org, project, env, "applications", name, {
          generation: 1, // stale: server is at 2 now
          spec: { image: "registry.ryvex.dev/checkout:1.2.0", replicas: 4 },
        });
      } catch (err) {
        conflict = err;
      }
      expect(conflict).toBeInstanceOf(RyvexError);
      if (!(conflict instanceof RyvexError)) throw new Error("expected RyvexError");
      expect(conflict.status).toBe(409);
      expect(conflict.code).toBe("conflict");

      // 7. fresh CAS write still succeeds (2 → 3)
      const again = await client.putInScope(org, project, env, "applications", name, {
        generation: 2,
        spec: { image: "registry.ryvex.dev/checkout:1.2.0", replicas: 4 },
      });
      expect(again.generation).toBe(3);

      // 8. manual reconcile trigger (202)
      const ack = await client.triggerReconcile(org, id);
      expect(ack.status).toBe("accepted");
      expect(ack.resource_id).toBe(id);

      // 9. observability eventually reflects the mutation
      const events = await client.events(org, { limit: 50 });
      expect(events.events.some((e) => e.resource_id === id && e.type === "updated")).toBeTrue();
      const audit = await client.audit(org, { limit: 50 });
      expect(audit.entries.some((e) => e.resource_id === id && e.action === "updated")).toBeTrue();

      // 10. delete by handle → subsequent gets 404
      await client.deleteResource(id);
      const err: unknown = await client.getResource(id).then(
        () => null,
        (e) => e,
      );
      expect(err).toBeInstanceOf(RyvexError);
      if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
      expect(err.status).toBe(404);
      expect(err.code).toBe("not_found");

      // done — skip the finally-block cleanup below
      return;
    } finally {
      // Best-effort cleanup so failed runs don't litter the store.
      // Ignored if the resource was already deleted above.
      await client
        .deleteInScope(org, project, env, "applications", name)
        .catch(() => undefined);
    }
  });
});
