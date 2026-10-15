package com.example.auditlog.api;

import com.example.auditlog.archival.ArchiveEventResult;
import com.example.auditlog.archival.AuditArchivalService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for audit event archival operations.
 *
 * <h2>Authorization</h2>
 *
 * <p>Both endpoints require the {@code AUDIT_WRITER} role. Archival is a controlled write-side
 * operation (inserting metadata into {@code audit_event_archive}); the {@code AUDITOR} role is
 * read-only and must not trigger archival.
 *
 * <h2>Endpoints</h2>
 *
 * <ul>
 *   <li>{@code POST /audit/archive/{eventId}} — archive a single event by UUID.
 *   <li>{@code POST /audit/archive/eligible} — batch-archive all events beyond the retention window.
 * </ul>
 *
 * <h2>Invariant</h2>
 *
 * <p>Archival never modifies {@code audit_event} rows. {@code GET /audit/verify} remains correct
 * for archived events because the original rows are always present with unmodified hashes.
 */
@RestController
@RequestMapping(path = "/audit/archive", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuditArchivalController {

    private static final Logger log = LoggerFactory.getLogger(AuditArchivalController.class);

    private final AuditArchivalService archivalService;

    public AuditArchivalController(AuditArchivalService archivalService) {
        this.archivalService = archivalService;
    }

    /**
     * Archives a single audit event by UUID.
     *
     * <p>If the event is already archived the existing archive record is returned (idempotent).
     * If the event does not exist, HTTP 404 is returned.
     *
     * @param eventId   the UUID of the event to archive
     * @param body      JSON object with {@code "policyRef"} (required, non-blank)
     * @return HTTP 200 with the archive record
     */
    @PostMapping(path = "/{eventId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ArchiveEventResult> archiveSingle(
            @PathVariable UUID eventId,
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {

        String policyRef = body != null ? body.get("policyRef") : null;
        if (policyRef == null || policyRef.isBlank()) {
            throw new IllegalArgumentException("policyRef must not be blank");
        }

        String correlationId = resolveCorrelationId(request);
        log.info("Archiving event: eventId={} policyRef={} correlationId={}", eventId, policyRef, correlationId);

        ArchiveEventResult result = archivalService.archive(eventId, policyRef);
        return ResponseEntity.ok(result);
    }

    /**
     * Batch-archives all events whose {@code recorded_at} is at or before the cutoff determined
     * by the configured retention window ({@code audit.retention.window-days}).
     *
     * @param body JSON object with {@code "policyRef"} (required, non-blank)
     * @return HTTP 200 with {@code {"archivedCount": N}}
     */
    @PostMapping(path = "/eligible", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Integer>> archiveEligible(
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {

        String policyRef = body != null ? body.get("policyRef") : null;
        if (policyRef == null || policyRef.isBlank()) {
            throw new IllegalArgumentException("policyRef must not be blank");
        }

        String correlationId = resolveCorrelationId(request);
        log.info("Batch archival requested: policyRef={} correlationId={}", policyRef, correlationId);

        int count = archivalService.archiveEligible(policyRef);
        return ResponseEntity.ok(Map.of("archivedCount", count));
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : java.util.UUID.randomUUID().toString();
    }
}
