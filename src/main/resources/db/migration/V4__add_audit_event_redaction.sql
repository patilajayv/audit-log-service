-- Milestone 10: Scenario B structured payload redaction metadata and lifecycle enforcement.
--
-- Records structured payload redaction operations. The original audit_event row
-- is NEVER modified or removed, preserving original content hashes, record hashes,
-- and chain continuity. GET /audit/verify continues to verify 100% of historical events.
--
-- Privileges: audit_app receives SELECT, INSERT on audit_event_redaction,
--             and UPDATE restricted ONLY to (status, redacted_at, meta_audit_sequence_no).
--             audit_app receives NO UPDATE rights on immutable metadata columns,
--             and NO DELETE or TRUNCATE rights.
--             Triggers prevent mutation after completion and prevent DELETE/TRUNCATE.

CREATE TABLE audit_event_redaction (
    redaction_id           BIGSERIAL    PRIMARY KEY,
    operation_id           VARCHAR(256) NOT NULL,
    event_id               UUID         NOT NULL REFERENCES audit_event(event_id) ON DELETE RESTRICT,
    field_path             VARCHAR(256) NOT NULL,
    redacted_at            TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason                 VARCHAR(128) NOT NULL,
    requested_by           VARCHAR(128) NOT NULL,
    redaction_type         VARCHAR(32)  NOT NULL DEFAULT 'MASKED',
    status                 VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    key_id                 VARCHAR(256),
    meta_audit_sequence_no BIGINT       REFERENCES audit_event(sequence_no),
    CONSTRAINT uq_audit_event_redaction_operation UNIQUE (operation_id),
    CONSTRAINT uq_audit_event_redaction_field UNIQUE (event_id, field_path),
    CONSTRAINT chk_redaction_type CHECK (redaction_type IN ('MASKED', 'CRYPTO_SHREDDED')),
    CONSTRAINT chk_redaction_status CHECK (status IN ('PENDING', 'KEY_DESTRUCTION_FAILED', 'KEY_DESTROYED', 'COMPLETED'))
);

CREATE INDEX idx_audit_event_redaction_event_id ON audit_event_redaction (event_id);
CREATE INDEX idx_audit_event_redaction_redacted_at ON audit_event_redaction (redacted_at);
CREATE INDEX idx_audit_event_redaction_status ON audit_event_redaction (status);

-- Partial unique index on audit_event for fast reconciliation and duplicate prevention of meta-audit events
CREATE UNIQUE INDEX idx_audit_event_meta_redaction_op ON audit_event ((payload->>'redactionOperationId'))
WHERE event_type = 'PAYLOAD_REDACTED';

REVOKE ALL ON TABLE audit_event_redaction FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE audit_event_redaction TO audit_app;
GRANT UPDATE (status, redacted_at, meta_audit_sequence_no) ON TABLE audit_event_redaction TO audit_app;
GRANT USAGE, SELECT ON SEQUENCE audit_event_redaction_redaction_id_seq TO audit_app;

CREATE OR REPLACE FUNCTION enforce_audit_event_redaction_lifecycle()
RETURNS TRIGGER AS $$
BEGIN
    -- 1. Disallow any mutation once record is COMPLETED (sealed)
    IF OLD.status = 'COMPLETED' THEN
        RAISE EXCEPTION 'audit_event_redaction record is sealed and immutable once COMPLETED'
            USING ERRCODE = '55000';
    END IF;

    -- 2. Guard against tampering with immutable metadata columns
    IF OLD.event_id IS DISTINCT FROM NEW.event_id OR
       OLD.field_path IS DISTINCT FROM NEW.field_path OR
       OLD.reason IS DISTINCT FROM NEW.reason OR
       OLD.requested_by IS DISTINCT FROM NEW.requested_by OR
       OLD.redaction_type IS DISTINCT FROM NEW.redaction_type OR
       OLD.key_id IS DISTINCT FROM NEW.key_id OR
       OLD.operation_id IS DISTINCT FROM NEW.operation_id THEN
        RAISE EXCEPTION 'Illegal mutation of immutable redaction metadata columns'
            USING ERRCODE = '55000';
    END IF;

    -- 3. Enforce valid state transitions:
    --    PENDING -> KEY_DESTRUCTION_FAILED, KEY_DESTROYED
    --    KEY_DESTRUCTION_FAILED -> PENDING, KEY_DESTROYED
    --    KEY_DESTROYED -> COMPLETED
    IF OLD.status <> NEW.status THEN
        IF OLD.status = 'PENDING' AND NEW.status NOT IN ('KEY_DESTRUCTION_FAILED', 'KEY_DESTROYED') THEN
            RAISE EXCEPTION 'Invalid transition from PENDING to %', NEW.status
                USING ERRCODE = '55000';
        END IF;

        IF OLD.status = 'KEY_DESTRUCTION_FAILED' AND NEW.status NOT IN ('PENDING', 'KEY_DESTROYED') THEN
            RAISE EXCEPTION 'Invalid transition from KEY_DESTRUCTION_FAILED to %', NEW.status
                USING ERRCODE = '55000';
        END IF;

        IF OLD.status = 'KEY_DESTROYED' AND NEW.status NOT IN ('COMPLETED') THEN
            RAISE EXCEPTION 'Invalid transition from KEY_DESTROYED to %', NEW.status
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- 4. Require valid positive meta_audit_sequence_no upon reaching COMPLETED
    IF NEW.status = 'COMPLETED' AND (NEW.meta_audit_sequence_no IS NULL OR NEW.meta_audit_sequence_no <= 0) THEN
        RAISE EXCEPTION 'Cannot transition redaction status to COMPLETED without a valid meta_audit_sequence_no'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_event_redaction_lifecycle
BEFORE UPDATE ON audit_event_redaction
FOR EACH ROW
EXECUTE FUNCTION enforce_audit_event_redaction_lifecycle();

CREATE OR REPLACE FUNCTION prevent_audit_event_redaction_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'DELETE and TRUNCATE are prohibited on audit_event_redaction'
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_event_redaction_no_delete
BEFORE DELETE ON audit_event_redaction
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_event_redaction_delete();
