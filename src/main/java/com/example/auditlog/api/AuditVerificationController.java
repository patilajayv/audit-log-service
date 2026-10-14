package com.example.auditlog.api;

import com.example.auditlog.verify.AuditVerificationResponse;
import com.example.auditlog.verify.AuditVerificationService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for full-chain cryptographic and structural verification.
 *
 * <p>Exposes {@code GET /audit/verify} to inspect the tamper-evident hash chain.
 * Operates strictly in read-only mode, preserves log privacy, and returns detailed
 * diagnostic status for both intact and corrupted chains.
 */
@RestController
@RequestMapping("/audit/verify")
public class AuditVerificationController {

    private static final Logger log = LoggerFactory.getLogger(AuditVerificationController.class);

    private final AuditVerificationService verificationService;

    public AuditVerificationController(AuditVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    /**
     * Inspects the complete global audit chain and returns its integrity status.
     *
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 200 OK with {@link AuditVerificationResponse} containing intact or corrupted status
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuditVerificationResponse> verifyChain(HttpServletRequest httpRequest) {
        String correlationId = resolveCorrelationId(httpRequest);
        log.debug("Processing audit chain verification request: correlationId={}", correlationId);

        AuditVerificationResponse response = verificationService.verifyChain();

        if (AuditVerificationResponse.STATUS_INTACT.equals(response.status())) {
            log.info("Audit chain verification completed successfully: status=INTACT, verifiedCount={}, correlationId={}",
                    response.recordsVerified(), correlationId);
        } else {
            log.warn("Audit chain verification detected inconsistency: status=CORRUPTED, violationType={}, sequenceNo={}, correlationId={}",
                    response.violation() != null ? response.violation().type() : "UNKNOWN",
                    response.violation() != null ? response.violation().sequenceNo() : -1,
                    correlationId);
        }

        return ResponseEntity.ok(response);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }
}
