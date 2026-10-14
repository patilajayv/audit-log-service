package com.example.auditlog.api;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.hashing.AuditHashService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for appending audit events to the global audit chain.
 *
 * <p>Enforces strict input validation, privacy safeguards (no sensitive payload/ID logging),
 * and returns the newly committed event position and cryptographic hashes.
 */
@RestController
@RequestMapping("/audit/events")
public class AuditEventController {

    private static final Logger log = LoggerFactory.getLogger(AuditEventController.class);

    private final AuditAppendService appendService;
    private final AuditHashService hashService;

    public AuditEventController(AuditAppendService appendService, AuditHashService hashService) {
        this.appendService = appendService;
        this.hashService = hashService;
    }

    /**
     * Appends a validated audit event to the tamper-evident hash chain.
     *
     * @param request the validated event request
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 201 Created with the assigned event ID, sequence number, and hashes
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuditEventResponse> appendEvent(
            @RequestBody AppendEventRequest request,
            HttpServletRequest httpRequest) {

        String correlationId = resolveCorrelationId(httpRequest);
        log.debug("Processing audit append request: correlationId={}", correlationId);

        AppendEventResult result = appendService.append(request);

        AuditEventResponse response = new AuditEventResponse(
                result.eventId(),
                result.sequenceNo(),
                hashService.formatTimestamp(result.recordedAt()),
                result.contentHash(),
                result.previousHash(),
                result.recordHash());

        log.info("Audit event committed successfully: eventId={}, sequenceNo={}, correlationId={}",
                result.eventId(), result.sequenceNo(), correlationId);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }
}
