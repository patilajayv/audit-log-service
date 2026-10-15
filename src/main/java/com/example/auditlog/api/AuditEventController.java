package com.example.auditlog.api;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.query.AuditQueryCriteria;
import com.example.auditlog.query.AuditQueryService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for writing and querying immutable audit events.
 *
 * <p>Enforces strict input validation, privacy safeguards (no sensitive payload/ID logging),
 * deterministic sequence-ordered pagination, and returns committed events with cryptographic hashes.
 */
@RestController
@RequestMapping("/audit/events")
public class AuditEventController {

    private static final Logger log = LoggerFactory.getLogger(AuditEventController.class);

    private final AuditAppendService appendService;
    private final AuditQueryService queryService;
    private final AuditHashService hashService;

    public AuditEventController(
            AuditAppendService appendService,
            AuditQueryService queryService,
            AuditHashService hashService) {
        this.appendService = appendService;
        this.queryService = queryService;
        this.hashService = hashService;
    }

    /**
     * Queries committed audit events matching the provided filter criteria with stable pagination.
     *
     * @param actorId optional filter by actor identifier
     * @param resourceType optional filter by resource type
     * @param resourceId optional filter by resource identifier
     * @param eventType optional filter by event type
     * @param from optional ISO-8601 start timestamp against service recorded_at (inclusive)
     * @param to optional ISO-8601 end timestamp against service recorded_at (inclusive)
     * @param page zero-based page index (default 0)
     * @param size page size (default 20, max 100)
     * @param httpRequest HTTP servlet request for correlation tracing
     * @return 200 OK with page results ordered monotonically by sequence_no ASC
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuditPageResponse<AuditEventDto>> queryEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false, defaultValue = "0") Integer page,
            @RequestParam(required = false, defaultValue = "20") Integer size,
            @RequestParam(required = false, defaultValue = "false") Boolean includeArchived,
            HttpServletRequest httpRequest) {

        String correlationId = resolveCorrelationId(httpRequest);
        log.debug("Processing audit query request: correlationId={}", correlationId);

        AuditQueryCriteria criteria = AuditQueryCriteria.of(
                actorId, resourceType, resourceId, eventType, from, to, page, size, includeArchived);

        AuditPageResponse<AuditEventDto> response = queryService.query(criteria);
        return ResponseEntity.ok(response);
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
