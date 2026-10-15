package com.example.auditlog.export;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.UUID;

/**
 * Full audit event record returned as part of a verifiable export bundle.
 *
 * <p>Contains the full canonical payload enabling independent recalculation of the
 * RFC 8785 canonical content hash and domain-separated record hash.
 *
 * <p>If the event was soft-archived, {@code archivedAt} contains the ISO-8601 UTC timestamp.
 * Stored cryptographic hashes remain identical to their original append-time commitments.
 *
 * <p>If the event underwent structured redaction, {@code redactionType} indicates
 * {@code "CRYPTO_SHREDDED"} (ciphertext envelope preserved, key destroyed, full content hash verified)
 * or {@code "MASKED"} (legacy plaintext masked with {@code "[REDACTED]"}, content hash unverifiable without plaintext).
 * {@code null} indicates an unredacted event.
 */
public record ExportEventDto(
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
        String archivedAt,
        String redactionType) {

    public ExportEventDto(
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
        this(sequenceNo, eventId, eventType, actorId, resourceType, resourceId, payload,
                sourceTimestamp, recordedAt, canonicalizationVersion, contentHash, previousHash, recordHash, archivedAt, null);
    }
}
