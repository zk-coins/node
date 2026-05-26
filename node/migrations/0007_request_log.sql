-- Full HTTP audit log: every request the node accepts is persisted
-- with its raw body, headers, and the bytes of the response that was
-- sent back. The node is not a privacy boundary — anyone who wants
-- shielded operation runs their own node; the operator-side
-- observation surface is fair game.
--
-- Storage notes
-- -------------
-- * `request_body` / `response_body` are BYTEA, NOT TEXT — request
--   payloads may be binary (multipart, msgpack-shaped frames, etc.)
--   and storing as text would force a charset round-trip we don't
--   want. Today every route is JSON, but the column type is the
--   conservative pick.
-- * `request_headers` / `response_headers` are JSONB to make the
--   ad-hoc forensics queries (`WHERE request_headers ->> 'user-agent'
--   LIKE '%wallet%'`) reasonable without a separate schema.
-- * `query` is the raw URL query string (post-`?`), nullable for
--   requests without one.
-- * `remote_addr` is the peer address axum's `ConnectInfo<SocketAddr>`
--   resolves to — i.e. the immediate TCP peer. Behind a reverse
--   proxy this is the proxy address; the actual client IP needs an
--   `X-Forwarded-For` header which is already captured in
--   `request_headers`.
-- * `duration_us` is wall-clock microseconds from the moment the
--   middleware first sees the request to the moment it forwards the
--   buffered response — a low-cost service-level latency metric that
--   does not need a separate Prometheus pipeline to be useful.
--
-- Indices
-- -------
-- * `request_log_received_at_idx` (DESC) for the bulk "what landed on
--   the last 24 h" queries and for retention pruning.
-- * `request_log_path_idx` for per-endpoint forensics
--   (`SELECT … WHERE path = '/api/mint' ORDER BY received_at DESC`).
--
-- Retention is deliberately not enforced by this migration. The
-- operator can decide what to keep — pruning is one `DELETE FROM
-- request_log WHERE received_at < NOW() - INTERVAL '30 days'` away.

CREATE TABLE request_log (
    id               BIGSERIAL    PRIMARY KEY,
    received_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    method           TEXT         NOT NULL,
    path             TEXT         NOT NULL,
    query            TEXT,
    remote_addr      TEXT,
    user_agent       TEXT,
    request_headers  JSONB        NOT NULL,
    request_body     BYTEA        NOT NULL,
    response_status  SMALLINT     NOT NULL,
    response_headers JSONB        NOT NULL,
    response_body    BYTEA        NOT NULL,
    duration_us      BIGINT       NOT NULL
);

CREATE INDEX request_log_received_at_idx ON request_log (received_at DESC);
CREATE INDEX request_log_path_idx        ON request_log (path, received_at DESC);
