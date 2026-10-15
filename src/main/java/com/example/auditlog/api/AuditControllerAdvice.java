package com.example.auditlog.api;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Centralized exception handler providing sanitized, structured error responses for the REST API.
 *
 * <p>Never leaks SQL details, database schema information, constraint names, or internal stack traces.
 * Does not log sensitive event payloads or identifiers.
 */
@RestControllerAdvice
public class AuditControllerAdvice {

    private static final Logger log = LoggerFactory.getLogger(AuditControllerAdvice.class);
    private static final Pattern DUPLICATE_FIELD_PATTERN = Pattern.compile("Duplicate (?:field|property) '?([^'\\s:]+)'?");

    private final Clock clock;

    public AuditControllerAdvice(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(PayloadTooLargeException.class)
    public ResponseEntity<ErrorResponse> handlePayloadTooLarge(
            PayloadTooLargeException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.warn("Payload too large: correlationId={}", correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.PAYLOAD_TOO_LARGE.value(),
                HttpStatus.PAYLOAD_TOO_LARGE.getReasonPhrase(),
                ex.getMessage(),
                clock.instant());
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(
            HttpMessageNotReadableException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        Throwable root = getRootCause(ex);

        if (root instanceof PayloadTooLargeException ptle) {
            return handlePayloadTooLarge(ptle, request);
        }

        String clientMessage;
        if (root instanceof IllegalArgumentException iae) {
            // Safe validation message from record constructor or numeric policy
            clientMessage = iae.getMessage();
        } else if (root instanceof JsonParseException jpe) {
            Matcher matcher = DUPLICATE_FIELD_PATTERN.matcher(jpe.getMessage());
            if (matcher.find()) {
                clientMessage = "Duplicate JSON property: '" + matcher.group(1) + "'";
            } else {
                clientMessage = "Malformed JSON request body";
            }
        } else if (root instanceof InvalidFormatException ife) {
            if (ife.getTargetType() != null && Instant.class.isAssignableFrom(ife.getTargetType())) {
                clientMessage = "Invalid timestamp format for sourceTimestamp; must be valid ISO-8601 timestamp";
            } else {
                clientMessage = "Invalid format for field in request body";
            }
        } else if (root instanceof DateTimeParseException) {
            clientMessage = "Invalid timestamp format for sourceTimestamp; must be valid ISO-8601 timestamp";
        } else if (root instanceof JsonMappingException jme && jme.getCause() instanceof IllegalArgumentException iae) {
            clientMessage = iae.getMessage();
        } else {
            clientMessage = "Malformed JSON request body";
        }

        log.debug("Bad request syntax or validation failure: correlationId={}", correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                clientMessage,
                clock.instant());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.debug("Validation rejection: correlationId={}", correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                ex.getMessage(),
                clock.instant());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(AuditEventNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAuditEventNotFound(
            AuditEventNotFoundException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.debug("Audit event not found: eventId={} correlationId={}", ex.getEventId(), correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                HttpStatus.NOT_FOUND.getReasonPhrase(),
                ex.getMessage(),
                clock.instant());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(com.example.auditlog.redaction.RedactionKeyDestructionException.class)
    public ResponseEntity<ErrorResponse> handleKeyDestructionException(
            com.example.auditlog.redaction.RedactionKeyDestructionException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.error("Key destruction failure during redaction: keyId={} correlationId={}", ex.getKeyId(), correlationId, ex);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.BAD_GATEWAY.value(),
                HttpStatus.BAD_GATEWAY.getReasonPhrase(),
                "Key destruction failed in Key Management Service",
                clock.instant());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(com.example.auditlog.append.IdempotencyConflictException.class)
    public ResponseEntity<ErrorResponse> handleIdempotencyConflict(
            com.example.auditlog.append.IdempotencyConflictException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.warn("Idempotency conflict: key={} correlationId={}", ex.getIdempotencyKey(), correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.CONFLICT.value(),
                HttpStatus.CONFLICT.getReasonPhrase(),
                ex.getMessage(),
                clock.instant());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.debug("Parameter type mismatch: correlationId={}", correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                "Invalid value for parameter '" + ex.getName() + "'",
                clock.instant());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex, HttpServletRequest request) {
        ErrorResponse body = new ErrorResponse(
                HttpStatus.UNSUPPORTED_MEDIA_TYPE.value(),
                HttpStatus.UNSUPPORTED_MEDIA_TYPE.getReasonPhrase(),
                "Content-Type must be application/json",
                clock.instant());
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
        ErrorResponse body = new ErrorResponse(
                HttpStatus.METHOD_NOT_ALLOWED.value(),
                HttpStatus.METHOD_NOT_ALLOWED.getReasonPhrase(),
                "HTTP method not supported",
                clock.instant());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler({
            CannotAcquireLockException.class,
            PessimisticLockingFailureException.class,
            QueryTimeoutException.class
    })
    public ResponseEntity<ErrorResponse> handleLockContention(
            Exception ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.warn("Chain-head lock contention: correlationId={}", correlationId);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(),
                "Temporary lock contention on the audit chain head. Please retry.",
                clock.instant());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header(HttpHeaders.RETRY_AFTER, "1")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler({DataAccessException.class, SQLException.class})
    public ResponseEntity<ErrorResponse> handleDatabaseError(
            Exception ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.error("Database error during audit event append: correlationId={}", correlationId, ex);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "An internal database error occurred while recording the audit event.",
                clock.instant());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, HttpServletRequest request) {
        String correlationId = resolveCorrelationId(request);
        log.error("Unhandled error during audit event append: correlationId={}", correlationId, ex);
        ErrorResponse body = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "An internal error occurred while processing the audit event.",
                clock.instant());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String header = request.getHeader("X-Correlation-ID");
        return (header != null && !header.isBlank()) ? header : UUID.randomUUID().toString();
    }

    private Throwable getRootCause(Throwable t) {
        Throwable curr = t;
        while (curr.getCause() != null && curr.getCause() != curr) {
            curr = curr.getCause();
        }
        return curr;
    }
}
