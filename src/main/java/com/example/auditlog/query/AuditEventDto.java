package com.example.auditlog.query;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.UUID;

/**
 * Data transfer object representing a committed, immutable audit event returned by the query API.
 *
 * <p>All fields reflect stored immutable database values. Hashes are lowercase hex SHA-256 strings;
 * timestamps are formatted in ISO-8601 UTC with millisecond precision.
 *
 * <p>{@code archivedAt} is non-null if the event has been soft-archived (a corresponding row
 * exists in {@code audit_event_archive}), and {@code null} otherwise.
 */
public record AuditEventDto(
        long sequenceNo,
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        String sourceTimestamp,
        String recordedAt,
        String canonicalizationVersion,
        String contentHash,
        String previousHash,
        String recordHash,
        String archivedAt) {

    public AuditEventDto(
            long sequenceNo,
            UUID eventId,
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            JsonNode payload,
            String sourceTimestamp,
            String recordedAt,
            String canonicalizationVersion,
            String contentHash,
            String previousHash,
            String recordHash) {
        this(sequenceNo, eventId, eventType, actorId, resourceType, resourceId, payload,
                sourceTimestamp, recordedAt, canonicalizationVersion, contentHash, previousHash, recordHash, null);
    }
}
