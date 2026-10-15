package com.example.auditlog.api;

import com.example.auditlog.redaction.AuditRedactionService;
import com.example.auditlog.redaction.RedactionRequest;
import com.example.auditlog.redaction.RedactionResult;
import jakarta.servlet.http.HttpServletRequest;
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
 * REST controller for structured audit event payload redaction.
 *
 * <h2>Authorization</h2>
 *
 * <p>Restricted to role {@code AUDIT_WRITER}. Redaction is an operational compliance write
 * that inserts metadata and appends a {@code PAYLOAD_REDACTED} event; the read-only {@code AUDITOR}
 * role is prohibited from triggering redactions.
 */
@RestController
@RequestMapping(path = "/audit/events", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuditRedactionController {

    private static final Logger log = LoggerFactory.getLogger(AuditRedactionController.class);

    private final AuditRedactionService redactionService;

    public AuditRedactionController(AuditRedactionService redactionService) {
        this.redactionService = redactionService;
    }

    /**
     * Redacts a specific field within an audit event's payload.
     *
     * @param eventId the UUID of the target event
     * @param request the redaction request specifying fieldPath, reason, and requestedBy
     * @return HTTP 200 with the redaction outcome
     */
    @PostMapping(path = "/{eventId}/redact", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RedactionResult> redactField(
            @PathVariable UUID eventId,
            @RequestBody RedactionRequest request,
            HttpServletRequest httpRequest) {

        String correlationId = resolveCorrelationId(httpRequest);
        log.info("Processing payload redaction request: eventId={} fieldPath={} correlationId={}",
                eventId, request.fieldPath(), correlationId);

        RedactionResult result = redactionService.redact(eventId, request);
        return ResponseEntity.ok(result);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }
}
