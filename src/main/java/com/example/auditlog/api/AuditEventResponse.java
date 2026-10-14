package com.example.auditlog.api;

import java.util.UUID;

/**
 * HTTP response payload returned upon successful creation of an audit event (HTTP 201 Created).
 *
 * <p>All fields are non-null. Hashes are 64-character lowercase hexadecimal SHA-256 digests.
 * {@code recordedAt} is formatted in ISO-8601 UTC with millisecond precision.
 */
public record AuditEventResponse(
        UUID eventId,
        long sequenceNo,
        String recordedAt,
        String contentHash,
        String previousHash,
        String recordHash) {}
