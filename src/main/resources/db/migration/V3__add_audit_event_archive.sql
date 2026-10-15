-- Milestone 9: Scenario B soft-archival metadata table.
--
-- Records soft-archival state for audit events that have passed the configured
-- retention window. The original audit_event row is NEVER modified or removed.
-- Verification always scans the full audit_event table including archived events;
-- no false-positive chain failures are introduced by archival.
--
-- Privileges: audit_app may INSERT and SELECT on this table.
--             audit_app receives NO UPDATE or DELETE rights on audit_event_archive.
--             audit_event rows and all existing triggers remain unchanged.

CREATE TABLE audit_event_archive (
    event_id         UUID        PRIMARY KEY REFERENCES audit_event(event_id),
    archived_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    policy_ref       TEXT        NOT NULL CHECK (btrim(policy_ref) <> ''),
    archive_location TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX audit_event_archive_archived_at_idx ON audit_event_archive (archived_at);

REVOKE ALL ON TABLE audit_event_archive FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE audit_event_archive TO audit_app;
