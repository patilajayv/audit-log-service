package com.example.auditlog.api;

import com.example.auditlog.compliance.AuditComplianceService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for regulator auditing and compliance reporting of client account data access.
 *
 * <p>Enforces:
 * <ul>
 *   <li>Mandatory, non-blank {@code accountId} parameter.</li>
 *   <li>Strict server-side isolation to {@code resourceType = 'ACCOUNT'}.</li>
 *   <li>Fail-closed supervisory audit trail for every examination query and export.</li>
 *   <li>Default inclusion of soft-archived records ({@code includeArchived = true}) for regulatory discovery.</li>
 * </ul>
 */
@RestController
@RequestMapping("/audit/compliance/account-access")
public class AuditComplianceController {

    private static final Logger log = LoggerFactory.getLogger(AuditComplianceController.class);

    private final AuditComplianceService complianceService;

    public AuditComplianceController(AuditComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    /**
     * Queries client account data access events with stable pagination and supervisory auditing.
     *
     * @param accountId required client account identifier
     * @param actorId optional filter by accessing actor
     * @param eventType optional filter by event type
     * @param from optional ISO-8601 UTC start time
     * @param to optional ISO-8601 UTC end time
     * @param page zero-based page index (defaults to 0)
     * @param size page size (defaults to 20, max 100)
     * @param includeArchived whether to include soft-archived events (defaults to true)
     * @param authentication Spring Security authentication principal
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 200 OK with stable page of account access events
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuditPageResponse<AuditEventDto>> queryAccountAccess(
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false, defaultValue = "0") Integer page,
            @RequestParam(required = false, defaultValue = "20") Integer size,
            @RequestParam(required = false, defaultValue = "true") Boolean includeArchived,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        if (accountId == null || accountId.trim().isEmpty()) {
            throw new IllegalArgumentException("'accountId' is required and must not be blank");
        }

        String correlationId = resolveCorrelationId(httpRequest);
        String principal = authentication != null ? authentication.getName() : "anonymous";
        log.debug("Processing compliance query request: accountId={}, principal={}, correlationId={}",
                accountId, principal, correlationId);

        AuditPageResponse<AuditEventDto> response = complianceService.queryAccountAccess(
                accountId.trim(),
                actorId,
                eventType,
                from,
                to,
                page,
                size,
                includeArchived,
                principal,
                correlationId);

        return ResponseEntity.ok(response);
    }

    /**
     * Generates a self-contained, verifiable export bundle strictly constrained to client account data.
     *
     * @param accountId required client account identifier
     * @param includeArchived whether to include soft-archived events (defaults to true)
     * @param authentication Spring Security authentication principal
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 200 OK with self-contained export bundle
     */
    @GetMapping(value = "/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ExportBundleDto> exportAccountAccess(
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false, defaultValue = "true") Boolean includeArchived,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        if (accountId == null || accountId.trim().isEmpty()) {
            throw new IllegalArgumentException("'accountId' is required and must not be blank");
        }

        String correlationId = resolveCorrelationId(httpRequest);
        String principal = authentication != null ? authentication.getName() : "anonymous";
        log.debug("Processing compliance export request: accountId={}, principal={}, correlationId={}",
                accountId, principal, correlationId);

        ExportBundleDto bundle = complianceService.exportAccountAccess(
                accountId.trim(),
                includeArchived,
                principal,
                correlationId);

        return ResponseEntity.ok(bundle);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String correlationId = request != null ? request.getHeader("X-Correlation-Id") : null;
        return (correlationId != null && !correlationId.isBlank())
                ? correlationId
                : UUID.randomUUID().toString();
    }
}
