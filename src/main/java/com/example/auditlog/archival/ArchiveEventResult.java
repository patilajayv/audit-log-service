package com.example.auditlog.archival;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents the result of a successful audit event archival operation.
 *
 * <p>Returned by {@link AuditArchivalService#archive} and serialized directly
 * as the HTTP 200 response body for {@code POST /audit/archive/{eventId}}.
 *
 * @param eventId         the UUID of the archived audit event
 * @param archivedAt      the UTC instant at which archival was recorded
 * @param policyRef       the policy label that triggered archival (non-blank)
 * @param archiveLocation optional contextual archival location (empty string when absent)
 */
public record ArchiveEventResult(
        UUID eventId,
        Instant archivedAt,
        String policyRef,
        String archiveLocation) {}
