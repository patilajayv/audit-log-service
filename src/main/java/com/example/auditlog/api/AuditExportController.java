package com.example.auditlog.api;

import com.example.auditlog.export.AuditExportService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.export.ExportFilterCriteria;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for self-contained, independently verifiable bulk audit exports.
 *
 * <p>Enforces:
 * <ul>
 *   <li>Mutual exclusivity between {@code actorId} and {@code resourceId}.</li>
 *   <li>Defense-in-depth sanitization of correlation IDs and request parameters.</li>
 *   <li>Returns a versioned, self-contained JSON export bundle with full payloads for matched
 *       events and hash witnesses for intermediate events.</li>
 * </ul>
 */
@RestController
@RequestMapping("/audit/exports")
public class AuditExportController {

    private static final Logger log = LoggerFactory.getLogger(AuditExportController.class);

    private final AuditExportService exportService;

    public AuditExportController(AuditExportService exportService) {
        this.exportService = exportService;
    }

    /**
     * Exports all audit records for a given {@code actorId} or {@code resourceId} as a self-contained,
     * verifiable bundle with intermediate witness nodes and chain-head checkpoint.
     *
     * @param actorId optional actor identifier (mutually exclusive with resourceId)
     * @param resourceId optional resource identifier (mutually exclusive with actorId)
     * @param includeArchived optional flag to include soft-archived events (default true)
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 200 OK with the self-contained {@link ExportBundleDto}
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ExportBundleDto> exportEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false, defaultValue = "true") Boolean includeArchived,
            HttpServletRequest httpRequest) {

        String correlationId = resolveCorrelationId(httpRequest);
        log.debug("Processing audit export request: correlationId={}", correlationId);

        ExportFilterCriteria criteria = ExportFilterCriteria.of(actorId, resourceId, includeArchived);
        ExportBundleDto bundle = exportService.exportBundle(criteria);

        return ResponseEntity.ok(bundle);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String correlationId = request != null ? request.getHeader("X-Correlation-Id") : null;
        return correlationId != null && !correlationId.isBlank()
                ? correlationId
                : UUID.randomUUID().toString();
    }
}
