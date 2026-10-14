package com.example.auditlog.append;

import java.time.Instant;
import java.util.UUID;

/**
 * Result returned to the caller after a successful audit event append.
 *
 * <p>All fields are non-null. Hashes are 64-character lowercase hexadecimal strings.
 */
public record AppendEventResult(
        UUID eventId,
        long sequenceNo,
        Instant recordedAt,
        String contentHash,
        String previousHash,
        String recordHash) {}
