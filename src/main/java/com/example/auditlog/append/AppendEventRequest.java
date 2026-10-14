package com.example.auditlog.append;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;

/**
 * Validated request to append a single audit event to the chain.
 *
 * <p>All string fields must be non-null and non-blank. {@code payload} must be a non-null
 * JSON object node. {@code sourceTimestamp} is optional; null is the absent sentinel.
 *
 * <p>Input validation is performed by {@link AuditAppendService#append(AppendEventRequest)}
 * before any database interaction.
 */
public record AppendEventRequest(
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        JsonNode payload,
        Instant sourceTimestamp) {

    /**
     * Validates that all required fields are present and non-blank.
     *
     * @throws IllegalArgumentException if any required field is null, blank, or if the payload
     *                                  is null or not a JSON object.
     */
    public AppendEventRequest {
        requireNonBlank(eventType, "eventType");
        requireNonBlank(actorId, "actorId");
        requireNonBlank(resourceType, "resourceType");
        requireNonBlank(resourceId, "resourceId");
        if (payload == null) {
            throw new IllegalArgumentException("payload must not be null");
        }
        if (!payload.isObject()) {
            throw new IllegalArgumentException("payload must be a JSON object");
        }
    }

    private static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
    }
}
