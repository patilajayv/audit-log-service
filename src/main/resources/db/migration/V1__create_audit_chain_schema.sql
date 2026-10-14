CREATE TABLE audit_chain_head (
    chain_id SMALLINT PRIMARY KEY CHECK (chain_id = 1),
    last_sequence_no BIGINT NOT NULL CHECK (last_sequence_no >= 0),
    last_record_hash VARCHAR(64) NOT NULL CHECK (last_record_hash ~ '^[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT audit_chain_head_empty_chain_uses_genesis_hash CHECK (
        last_sequence_no > 0 OR last_record_hash = repeat('0', 64)
    )
);

INSERT INTO audit_chain_head (chain_id, last_sequence_no, last_record_hash)
VALUES (1, 0, repeat('0', 64));

CREATE TABLE audit_event (
    sequence_no BIGINT PRIMARY KEY CHECK (sequence_no > 0),
    event_id UUID NOT NULL UNIQUE,
    event_type TEXT NOT NULL CHECK (btrim(event_type) <> ''),
    actor_id TEXT NOT NULL CHECK (btrim(actor_id) <> ''),
    resource_type TEXT NOT NULL CHECK (btrim(resource_type) <> ''),
    resource_id TEXT NOT NULL CHECK (btrim(resource_id) <> ''),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    source_timestamp TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL,
    canonicalization_version VARCHAR(32) NOT NULL CHECK (btrim(canonicalization_version) <> ''),
    content_hash VARCHAR(64) NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    previous_hash VARCHAR(64) NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    record_hash VARCHAR(64) NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX audit_event_actor_sequence_idx ON audit_event (actor_id, sequence_no);
CREATE INDEX audit_event_resource_sequence_idx ON audit_event (resource_type, resource_id, sequence_no);
CREATE INDEX audit_event_type_sequence_idx ON audit_event (event_type, sequence_no);
CREATE INDEX audit_event_recorded_at_sequence_idx ON audit_event (recorded_at, sequence_no);

CREATE FUNCTION prevent_audit_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_event_reject_update_delete
BEFORE UPDATE OR DELETE ON audit_event
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_event_mutation();

CREATE TRIGGER audit_event_reject_truncate
BEFORE TRUNCATE ON audit_event
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_audit_event_mutation();

CREATE FUNCTION enforce_chain_head_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.chain_id <> OLD.chain_id THEN
        RAISE EXCEPTION 'audit_chain_head identity cannot change'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.last_sequence_no <> OLD.last_sequence_no + 1 THEN
        RAISE EXCEPTION 'audit_chain_head sequence must advance by one'
            USING ERRCODE = '55000';
    END IF;

    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_chain_head_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain_head cannot be deleted or truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_chain_head_enforce_transition
BEFORE UPDATE ON audit_chain_head
FOR EACH ROW
EXECUTE FUNCTION enforce_chain_head_transition();

CREATE TRIGGER audit_chain_head_reject_delete
BEFORE DELETE ON audit_chain_head
FOR EACH ROW
EXECUTE FUNCTION prevent_chain_head_deletion();

CREATE TRIGGER audit_chain_head_reject_truncate
BEFORE TRUNCATE ON audit_chain_head
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_chain_head_deletion();

REVOKE ALL ON TABLE audit_event FROM PUBLIC;
REVOKE ALL ON TABLE audit_chain_head FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO audit_app;
GRANT SELECT, INSERT ON TABLE audit_event TO audit_app;
GRANT SELECT, UPDATE ON TABLE audit_chain_head TO audit_app;
