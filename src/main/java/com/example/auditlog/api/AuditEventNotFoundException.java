package com.example.auditlog.api;

import java.util.UUID;

/**
 * Thrown when an audit event is referenced by UUID but does not exist in {@code audit_event}.
 *
 * <p>Mapped to HTTP 404 by {@link AuditControllerAdvice}.
 */
public class AuditEventNotFoundException extends RuntimeException {

    private final UUID eventId;

    public AuditEventNotFoundException(UUID eventId) {
        super("Audit event not found: " + eventId);
        this.eventId = eventId;
    }

    public UUID getEventId() {
        return eventId;
    }
}
