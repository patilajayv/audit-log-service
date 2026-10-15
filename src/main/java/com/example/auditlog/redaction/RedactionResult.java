package com.example.auditlog.redaction;

import java.time.Instant;
import java.util.UUID;

/**
 * Result returned upon successful redaction of an audit event field.
 *
 * @param eventId              the UUID of the targeted audit event
 * @param fieldPath            the redacted field path within the event's payload
 * @param redactedAt           UTC timestamp when redaction reached terminal COMPLETED status
 * @param reason               compliance or operational justification
 * @param requestedBy          identity of the authorizing compliance principal
 * @param redactionType        "CRYPTO_SHREDDED" for envelope fields; "MASKED" for legacy plaintext
 * @param status               lifecycle state: "COMPLETED"
 * @param metaAuditSequenceNo  the sequence number of the immutable PAYLOAD_REDACTED event appended to the ledger
 */
public record RedactionResult(
        UUID eventId,
        String fieldPath,
        Instant redactedAt,
        String reason,
        String requestedBy,
        String redactionType,
        String status,
        Long metaAuditSequenceNo) {}
