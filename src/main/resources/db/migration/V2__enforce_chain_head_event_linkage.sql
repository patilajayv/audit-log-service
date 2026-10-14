DO $$
DECLARE
    current_head audit_chain_head%ROWTYPE;
    event_row audit_event%ROWTYPE;
    chain_head_count INTEGER;
    event_count BIGINT := 0;
    expected_sequence_no BIGINT := 1;
    expected_previous_hash VARCHAR(64) := repeat('0', 64);
    last_sequence_no BIGINT := 0;
BEGIN
    SELECT count(*)
    INTO chain_head_count
    FROM audit_chain_head;

    IF chain_head_count <> 1 THEN
        RAISE EXCEPTION 'existing audit-chain data is inconsistent: expected exactly one chain-head row'
            USING ERRCODE = '55000';
    END IF;

    SELECT *
    INTO current_head
    FROM audit_chain_head
    WHERE chain_id = 1;

    IF current_head.last_sequence_no < 0
       OR current_head.last_record_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'existing audit-chain data is inconsistent: invalid chain-head state'
            USING ERRCODE = '55000';
    END IF;

    FOR event_row IN
        SELECT *
        FROM audit_event
        ORDER BY sequence_no
    LOOP
        event_count := event_count + 1;

        IF event_row.sequence_no <> expected_sequence_no THEN
            RAISE EXCEPTION 'existing audit-chain data is inconsistent: event sequences are not contiguous'
                USING ERRCODE = '55000';
        END IF;

        IF event_row.previous_hash <> expected_previous_hash THEN
            RAISE EXCEPTION 'existing audit-chain data is inconsistent: event previous hash does not match the preceding record'
                USING ERRCODE = '55000';
        END IF;

        expected_previous_hash := event_row.record_hash;
        last_sequence_no := event_row.sequence_no;
        expected_sequence_no := expected_sequence_no + 1;
    END LOOP;

    IF event_count = 0 THEN
        IF current_head.last_sequence_no <> 0
           OR current_head.last_record_hash <> repeat('0', 64) THEN
            RAISE EXCEPTION 'existing audit-chain data is inconsistent: empty chain must use the genesis head'
                USING ERRCODE = '55000';
        END IF;
    ELSIF current_head.last_sequence_no <> event_count
       OR current_head.last_sequence_no <> last_sequence_no
       OR current_head.last_record_hash <> expected_previous_hash THEN
        RAISE EXCEPTION 'existing audit-chain data is inconsistent: chain head does not match the event chain'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_audit_event_append()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_head audit_chain_head%ROWTYPE;
BEGIN
    SELECT *
    INTO current_head
    FROM audit_chain_head
    WHERE chain_id = 1
    FOR UPDATE;

    IF NEW.sequence_no <> current_head.last_sequence_no + 1 THEN
        RAISE EXCEPTION 'audit_event sequence must append immediately after the chain head'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.previous_hash <> current_head.last_record_hash THEN
        RAISE EXCEPTION 'audit_event previous hash must match the chain head'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_enforce_append
BEFORE INSERT ON audit_event
FOR EACH ROW
EXECUTE FUNCTION enforce_audit_event_append();

CREATE OR REPLACE FUNCTION enforce_chain_head_transition()
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

    IF NOT EXISTS (
        SELECT 1
        FROM audit_event
        WHERE sequence_no = NEW.last_sequence_no
          AND previous_hash = OLD.last_record_hash
          AND record_hash = NEW.last_record_hash
    ) THEN
        RAISE EXCEPTION 'audit_chain_head must reference the next linked audit event'
            USING ERRCODE = '55000';
    END IF;

    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION require_audit_event_chain_head_advance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_head audit_chain_head%ROWTYPE;
BEGIN
    SELECT *
    INTO current_head
    FROM audit_chain_head
    WHERE chain_id = 1;

    IF current_head.last_sequence_no <> NEW.sequence_no
       OR current_head.last_record_hash <> NEW.record_hash THEN
        RAISE EXCEPTION 'audit_event insert must advance the chain head in the same transaction'
            USING ERRCODE = '55000';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER audit_event_requires_chain_head_advance
AFTER INSERT ON audit_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION require_audit_event_chain_head_advance();
