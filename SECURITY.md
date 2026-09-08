# Security Policy

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security problems.

Report through **GitHub Security Advisories**: on this repository, go to
**Security → Advisories → Report a vulnerability**. This keeps the report
private, lets us coordinate a fix, and credits you on disclosure if you
wish.

Contact placeholder for private follow-up: **security@ryvex.example**
(replace with the project's monitored mailbox).

Please include: affected component/surface, a minimal reproduction, the
version (`ryvexd version`) or commit, and your assessment of impact and
exploitability.

## Supported versions

Ryvex is pre-tags; versions below match the `ryvexd` release line (see
`cmd/ryvexd` `Version` and `CHANGELOG.md`).

| Version | Status | Security fixes |
|---------|--------|----------------|
| 1.1.x | Current release | ✅ Yes |
| 1.0.x | Legacy | ❌ No — upgrade to 1.1.x |

## Scope

**In scope:**

- `ryvexd` control plane: `/v1` REST API, auth (static + managed `ryk_`
  keys, RBAC scoping), CAS/generation semantics
- Webhook subsystem: SSRF egress guard, signature verification, dispatch
- Durable backends: Postgres store, NATS JetStream bus (isolation,
  credential handling, redaction)
- Console: trust model (live vs. demo modes, token handling, CORS)
- Node agent (Rust): enrollment, credentials at rest, command surface
- SDKs: credential handling, TLS/transport behavior

**Out of scope:**

- The console's **demo mode** rendering bundled sample data when no API
  base is configured — by design, and labelled as demo
- `/healthz` being unauthenticated — documented in
  `docs/api-contracts.md`
- Anything in `NEXT_PUBLIC_*` environment variables being visible to
  browsers — inherent to the Next.js public-env contract
- The `Secret` resource kind storing provider *references*, not
  plaintext values (it is a pointer to your external secret store)
- Denial-of-service via volumetric attacks, social engineering, or
  attacks requiring physical access

## Disclosure timeline

- **72 hours**: acknowledgement of your report
- **7 days**: triage result (accepted / declined, with rationale)
- **30 days**: fix or mitigation shipped for accepted reports in the
  current release line, followed by coordinated disclosure

## Hardening posture (for reviewers)

Security-sensitive PRs should call out: authz coverage of new routes,
SSRF/redaction implications of new egress, and CAS races. See the
existing hardening batches in `git log` (e.g. #36 webhook SSRF egress
guard, #38 API hardening) for the expected bar.
