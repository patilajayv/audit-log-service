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
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for writing and querying immutable audit events with idempotent replay protection.
 *
 * <p>Enforces strict input validation, privacy safeguards (no sensitive payload/ID logging),
 * deterministic sequence-ordered pagination, and returns committed events with cryptographic hashes.
 */
@RestController
@RequestMapping("/audit/events")
public class AuditEventController {

    private static final Logger log = LoggerFactory.getLogger(AuditEventController.class);
    private static final Pattern VALID_KEY_PATTERN = Pattern.compile("^[A-Za-z0-9_.:\\-]{1,256}$");

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
     * Appends a validated audit event to the tamper-evident hash chain with optional idempotency protection.
     *
     * @param request the validated event request
     * @param httpRequest HTTP servlet request for correlation tracing and header inspection
     * @return 201 Created on fresh append, or 200 OK on identical replay
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuditEventResponse> appendEvent(
            @RequestBody AppendEventRequest request,
            HttpServletRequest httpRequest) {

        String correlationId = resolveCorrelationId(httpRequest);
        String clientId = resolveClientId();

        String canonicalKey = httpRequest.getHeader("Idempotency-Key");
        String fallbackKey = httpRequest.getHeader("X-Idempotency-Key");
        String idempotencyKey = resolveAndValidateIdempotencyKey(canonicalKey, fallbackKey);

        log.debug("Processing audit append request: correlationId={}, clientId={}, idempotencyKey={}",
                correlationId, clientId, idempotencyKey);

        AppendEventResult result = appendService.appendWithIdempotency(request, clientId, idempotencyKey);

        AuditEventResponse response = new AuditEventResponse(
                result.eventId(),
                result.sequenceNo(),
                hashService.formatTimestamp(result.recordedAt()),
                result.contentHash(),
                result.previousHash(),
                result.recordHash());

        if (result.isReplay()) {
            log.info("Idempotent replay detected: eventId={}, sequenceNo={}, correlationId={}",
                    result.eventId(), result.sequenceNo(), correlationId);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }

        log.info("Audit event committed successfully: eventId={}, sequenceNo={}, correlationId={}",
                result.eventId(), result.sequenceNo(), correlationId);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    private String resolveAndValidateIdempotencyKey(String canonicalKey, String fallbackKey) {
        if (canonicalKey != null && fallbackKey != null && !canonicalKey.equals(fallbackKey)) {
            throw new IllegalArgumentException(
                    "Conflicting idempotency headers provided: Idempotency-Key and X-Idempotency-Key must match");
        }

        String rawKey = (canonicalKey != null) ? canonicalKey : fallbackKey;
        if (rawKey == null) {
            return null;
        }

        if (rawKey.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key header must not be blank");
        }

        if (rawKey.length() > 256) {
            throw new IllegalArgumentException("Idempotency-Key exceeds maximum allowed length of 256 characters");
        }

        if (!VALID_KEY_PATTERN.matcher(rawKey).matches()) {
            throw new IllegalArgumentException(
                    "Idempotency-Key contains invalid characters. Permitted characters are alphanumeric, '.', '-', '_', and ':'");
        }

        return rawKey;
    }

    private String resolveClientId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            String name = auth.getName();
            if (name != null && !name.isBlank()) {
                return name;
            }
        }
        return "anonymous";
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }
}
