package com.example.auditlog.hashing;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.UUID;

/**
 * Immutable value object representing the fields that are covered by {@code content_hash}.
 *
 * <p>This is the canonical event content shape, as specified in ARCHITECTURE.md §"Hash chain":
 *
 * <pre>{@code
 * {
 *   "canonicalizationVersion": "JCS-1",
 *   "eventId": "<uuid>",
 *   "eventType": "...",
 *   "actorId": "...",
 *   "resourceType": "...",
 *   "resourceId": "...",
 *   "payload": { ... },
 *   "sourceTimestamp": "<ISO-8601-ms-UTC> | null",
 *   "recordedAt": "<ISO-8601-ms-UTC>"
 * }
 * }</pre>
 *
 * <p>{@code sourceTimestamp} is represented as JSON {@code null} when absent. All timestamps
 * use UTC and millisecond precision.
 */
public record CanonicalEventContent(
        String canonicalizationVersion,
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        Instant sourceTimestamp, // null when absent
        Instant recordedAt) {}
