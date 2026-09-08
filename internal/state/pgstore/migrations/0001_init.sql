-- 0001_init.sql — initial Ryvex state schema.
--
-- resources: one row per declarative resource. The logical address
-- (org, project, env, kind, name) is unique; id is an opaque "r-<hex>"
-- handle. spec/labels are jsonb; the reconciler-owned status is
-- flattened into phase/message/observed_gen/status_updated_at.
CREATE TABLE IF NOT EXISTS resources (
    id                text PRIMARY KEY,
    org               text        NOT NULL,
    project           text        NOT NULL,
    env               text        NOT NULL,
    kind              text        NOT NULL,
    name              text        NOT NULL,
    generation        bigint      NOT NULL,
    labels            jsonb       NOT NULL,
    spec              jsonb       NOT NULL,
    phase             text        NOT NULL DEFAULT '',
    message           text        NOT NULL DEFAULT '',
    observed_gen      bigint      NOT NULL DEFAULT 0,
    status_updated_at timestamptz,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    CONSTRAINT resources_logical_key UNIQUE (org, project, env, kind, name)
);

-- Stable pagination order (created_at, id) and scope filters.
CREATE INDEX IF NOT EXISTS resources_created_idx ON resources (created_at, id);
CREATE INDEX IF NOT EXISTS resources_scope_idx   ON resources (org, project, env, kind);

-- audit: append-only trail. seq is a monotonic insertion sequence used
-- as the deterministic newest-first tie-breaker (timestamps only carry
-- microsecond precision); id is the public "a-<hex>" handle.
CREATE TABLE IF NOT EXISTS audit (
    seq         bigserial   NOT NULL UNIQUE,
    id          text PRIMARY KEY,
    ts          timestamptz NOT NULL,
    actor       text        NOT NULL,
    action      text        NOT NULL,
    resource_id text        NOT NULL DEFAULT '',
    kind        text        NOT NULL DEFAULT '',
    logical_key text        NOT NULL DEFAULT '',
    generation  bigint      NOT NULL DEFAULT 0,
    reason      text        NOT NULL DEFAULT ''
);

-- Prefix scans for the org filter (logical_key LIKE 'org/%').
CREATE INDEX IF NOT EXISTS audit_logical_key_idx ON audit (logical_key text_pattern_ops);
CREATE INDEX IF NOT EXISTS audit_ts_idx          ON audit (ts DESC);
