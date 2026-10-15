-- Milestone: Replay and Idempotency Protection for Audit Event Ingestion
--
-- Adds idempotent request tracking for POST /audit/events.
-- Scoped to (client_id, idempotency_key).
-- The referenced audit_event row is immutable and append-only.
--
-- Privileges: audit_app receives SELECT and INSERT rights only.
--             No UPDATE, DELETE, or TRUNCATE rights are granted.

CREATE TABLE audit_idempotency_key (
    idempotency_key VARCHAR(256) NOT NULL,
    client_id       VARCHAR(128) NOT NULL,
    request_hash    VARCHAR(64)  NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    event_id        UUID         NOT NULL REFERENCES audit_event(event_id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_audit_idempotency_key PRIMARY KEY (client_id, idempotency_key)
);

CREATE INDEX idx_audit_idempotency_created_at ON audit_idempotency_key (created_at);

REVOKE ALL ON TABLE audit_idempotency_key FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE audit_idempotency_key TO audit_app;
