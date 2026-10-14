package com.example.auditlog.query;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Validated criteria and pagination limits for querying audit events.
 *
 * <p>All string filters are trimmed; blank values are rejected. Time bounds are parsed to UTC
 * {@link Instant} values and validated such that {@code from <= to}.
 */
public record AuditQueryCriteria(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        Instant from,
        Instant to,
        int page,
        int size) {

    public static final int DEFAULT_PAGE = 0;
    public static final int DEFAULT_SIZE = 20;
    public static final int MAX_SIZE = 100;

    public AuditQueryCriteria {
        if (page < 0) {
            throw new IllegalArgumentException("page must not be negative");
        }
        if (size < 1 || size > MAX_SIZE) {
            throw new IllegalArgumentException("size must be between 1 and " + MAX_SIZE);
        }
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("'from' timestamp must not be after 'to' timestamp");
        }
    }

    public static AuditQueryCriteria of(
            String actorId,
            String resourceType,
            String resourceId,
            String eventType,
            String fromStr,
            String toStr,
            Integer page,
            Integer size) {

        int resolvedPage = page != null ? page : DEFAULT_PAGE;
        int resolvedSize = size != null ? size : DEFAULT_SIZE;

        String cleanActorId = cleanString(actorId, "actorId");
        String cleanResourceType = cleanString(resourceType, "resourceType");
        String cleanResourceId = cleanString(resourceId, "resourceId");
        String cleanEventType = cleanString(eventType, "eventType");

        Instant from = parseTimestamp(fromStr, "from");
        Instant to = parseTimestamp(toStr, "to");

        return new AuditQueryCriteria(
                cleanActorId, cleanResourceType, cleanResourceId, cleanEventType,
                from, to, resolvedPage, resolvedSize);
    }

    private static String cleanString(String val, String fieldName) {
        if (val == null) {
            return null;
        }
        String trimmed = val.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be blank if provided");
        }
        return trimmed;
    }

    private static Instant parseTimestamp(String tsStr, String paramName) {
        if (tsStr == null) {
            return null;
        }
        String trimmed = tsStr.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(paramName + " must not be blank if provided");
        }
        try {
            return Instant.parse(trimmed);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(
                    "Invalid timestamp format for '" + paramName + "'; must be valid ISO-8601 timestamp");
        }
    }
}
