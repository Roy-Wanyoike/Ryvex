/**
 * Parity test: SDK `RESOURCE_KINDS` vs the server's kind registry.
 *
 * Issue #79: the TS `ResourceKind` union had silently drifted from
 * `internal/state/resource.go` (11 kinds vs the server's 13) with
 * nothing to catch the gap. This test reads the Go source directly —
 * no checked-in fixture copy to go stale — extracts the registered
 * kinds, and fails the suite the moment either side adds or removes a
 * kind without the matching change on the other.
 *
 * Extraction strategy:
 *   1. Split resource.go into its top-level `const (...)` / `var ... {`
 *      blocks (gofmt keeps the delimiters at column 0).
 *   2. The kind-registry const block is the one declaring `Kind*` =
 *      "Literal" pairs; the authoritative set is the `var Kinds =
 *      map[string]bool{...}` block that references those constants.
 *   3. Resolve map identifiers through the const literals and compare
 *      the resulting string set with `RESOURCE_KINDS`.
 *
 * If the Go source is not on disk (e.g. the published npm tarball ships
 * the test files without the repo), the parity assertions skip instead
 * of failing; inside the repository the file always exists and the gate
 * is hard.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { RESOURCE_KINDS, type ResourceKind } from "../src/index.js";

const GO_RESOURCE = resolve(import.meta.dir, "../../../internal/state/resource.go");

const goSource: string | null = (() => {
  try {
    return readFileSync(GO_RESOURCE, "utf8");
  } catch {
    return null;
  }
})();

const exists = goSource !== null;

/** Split a Go source file into its top-level paren/brace-delimited blocks. */
function topLevelBlocks(src: string): string[] {
  const blocks: string[] = [];
  let current: string[] | null = null;
  for (const line of src.split("\n")) {
    if (current === null) {
      // gofmt keeps block delimiters at column 0: `const (`, `var Kinds = map[string]bool{`
      if (/^const \($/.test(line) || /^var Kinds = map\[string\]bool\{$/.test(line)) {
        current = [line];
      }
      continue;
    }
    current.push(line);
    if (line === ")" || line === "}") {
      blocks.push(current.join("\n"));
      current = null;
    }
  }
  return blocks;
}

// One extraction pass, shared by all assertions below.
const blocks = exists ? topLevelBlocks(goSource) : [];
const constBlock = blocks.find((b) => /^\s*Kind\w+\s*=\s*"/m.test(b));
const mapBlock = blocks.find((b) => b.startsWith("var Kinds ="));

/** Kind identifier -> string literal, from the registry const block. */
const declared = new Map<string, string>();
if (constBlock) {
  for (const m of constBlock.matchAll(/(Kind\w+)\s*=\s*"([^"]+)"/g)) {
    if (m[1] === undefined || m[2] === undefined) throw new Error("unreachable: capture groups always present");
    declared.set(m[1], m[2]);
  }
}

/** Kind identifiers referenced by the authoritative `Kinds` map. */
const registeredIds = mapBlock
  ? [...mapBlock.matchAll(/\b(Kind\w+)\s*:/g)].map((m) => m[1]).filter((id): id is string => id !== undefined)
  : [];

describe("kind parity: sdk/ryvex-ts vs internal/state/resource.go (#79)", () => {
  test("RESOURCE_KINDS entries are all valid ResourceKind literals", () => {
    // The type is derived from the const array, so this holds by
    // construction — it pins that invariant against accidental widening.
    const kinds: readonly ResourceKind[] = RESOURCE_KINDS;
    expect(kinds.length).toBe(RESOURCE_KINDS.length);
  });

  test("RESOURCE_KINDS has no duplicates", () => {
    expect(new Set(RESOURCE_KINDS).size).toBe(RESOURCE_KINDS.length);
  });

  test.skipIf(!exists)(
    "kind registry extracted from resource.go (parse sanity)",
    () => {
      expect(constBlock, "could not locate the Kind* const block in resource.go").toBeDefined();
      expect(mapBlock, "could not locate the `var Kinds = map[string]bool{...}` block in resource.go").toBeDefined();
      expect(declared.size).toBeGreaterThan(0);
      expect(registeredIds.length).toBeGreaterThan(0);
    },
  );

  test.skipIf(!exists)(
    "every Kind* constant is registered in the server's Kinds map",
    () => {
      // Mirrors the Go comment: "New kinds must be added here and in Kinds below."
      expect(new Set(registeredIds)).toEqual(new Set(declared.keys()));
    },
  );

  test.skipIf(!exists)(
    "SDK RESOURCE_KINDS == server registry (set equality)",
    () => {
      const resolveKind = (id: string): string => {
        const literal = declared.get(id);
        if (literal === undefined) {
          throw new Error(
            `resource.go: Kinds map references ${id} but no Kind* = "..." literal is declared for it`,
          );
        }
        return literal;
      };
      const serverKinds = registeredIds.map(resolveKind);
      const serverSet = new Set<string>(serverKinds);
      const sdkSet = new Set<string>(RESOURCE_KINDS);
      const serverOnly = serverKinds.filter((k) => !sdkSet.has(k));
      const sdkOnly = RESOURCE_KINDS.filter((k) => !serverSet.has(k));
      if (serverOnly.length > 0 || sdkOnly.length > 0) {
        throw new Error(
          `ResourceKind drift detected (issue #79 contract): ` +
            `server-only [${serverOnly.join(", ")}], SDK-only [${sdkOnly.join(", ")}]. ` +
            `Update RESOURCE_KINDS in sdk/ryvex-ts/src/types.ts together with internal/state/resource.go.`,
        );
      }
      expect(serverOnly).toEqual([]);
      expect(sdkOnly).toEqual([]);
    },
  );
});
