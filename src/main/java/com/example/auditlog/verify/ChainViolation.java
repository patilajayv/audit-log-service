package com.example.auditlog.verify;

import java.util.UUID;

/**
 * Diagnostic record detailing a detected audit chain inconsistency or cryptographic mismatch.
 *
 * @param type the category of violation detected
 * @param sequenceNo the sequence number at which the inconsistency occurred
 * @param eventId the unique event identifier (may be null if missing or sequence gap)
 * @param expected the expected value (e.g. expected hash or sequence)
 * @param actual the actual value observed in the database
 * @param message human-readable sanitized diagnostic message
 */
public record ChainViolation(
        ChainViolationType type,
        long sequenceNo,
        UUID eventId,
        String expected,
        String actual,
        String message) {}
