package com.example.auditlog.append;

import java.time.Instant;
import java.util.UUID;

/**
 * Result returned to the caller after a successful audit event append or idempotent replay.
 *
 * <p>All hash fields are non-null 64-character lowercase hexadecimal strings.
 * {@code isReplay} indicates whether this result was fulfilled from an existing idempotent operation.
 */
public record AppendEventResult(
        UUID eventId,
        long sequenceNo,
        Instant recordedAt,
        String contentHash,
        String previousHash,
        String recordHash,
        boolean isReplay) {

    /**
     * Backward-compatible constructor for non-replay appends.
     */
    public AppendEventResult(
            UUID eventId,
            long sequenceNo,
            Instant recordedAt,
            String contentHash,
            String previousHash,
            String recordHash) {
        this(eventId, sequenceNo, recordedAt, contentHash, previousHash, recordHash, false);
    }
}
