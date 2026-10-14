package com.example.auditlog.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.query.AuditQueryService;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import com.example.auditlog.security.SecurityConfiguration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@link AuditEventController} validating HTTP contracts,
 * input validation, duplicate key detection, request-size limits (HTTP 413),
 * timestamp normalization, error sanitization, and status codes.
 */
@WebMvcTest(AuditEventController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-writer", roles = "AUDIT_WRITER")
class AuditEventControllerWebMvcTest {

    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant RECORDED_AT = Instant.parse("2026-10-15T02:30:00.456Z");
    private static final String CONTENT_HASH = "4adef4d4355b8181195edbafb7dd255548eadf027fcc289c01b2cf5666530b26";
    private static final String PREVIOUS_HASH = "0".repeat(64);
    private static final String RECORD_HASH = "d4fdc27004f4d0ab21f89b9259ea15175f0a7b85fcc6bfa2c0bb1713c573e00e";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuditAppendService appendService;

    @MockBean
    private AuditQueryService queryService;

    @BeforeEach
    void setUp() {
        when(appendService.append(any(AppendEventRequest.class)))
                .thenReturn(new AppendEventResult(
                        EVENT_ID, 1L, RECORDED_AT, CONTENT_HASH, PREVIOUS_HASH, RECORD_HASH));
    }

    // -------------------------------------------------------------------------
    // Success Cases (HTTP 201 Created)
    // -------------------------------------------------------------------------

    @Test
    void successfulAppendReturns201WithEventIdSequenceAndHashes() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {
                        "ip": "192.168.1.1",
                        "authMethod": "MFA"
                    },
                    "sourceTimestamp": "2026-10-15T02:00:00.123Z"
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventId").value(EVENT_ID.toString()))
                .andExpect(jsonPath("$.sequenceNo").value(1))
                .andExpect(jsonPath("$.recordedAt").value("2026-10-15T02:30:00.456Z"))
                .andExpect(jsonPath("$.contentHash").value(CONTENT_HASH))
                .andExpect(jsonPath("$.previousHash").value(PREVIOUS_HASH))
                .andExpect(jsonPath("$.recordHash").value(RECORD_HASH));
    }

    @Test
    void acceptsOmittedSourceTimestamp() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated());

        ArgumentCaptor<AppendEventRequest> captor = ArgumentCaptor.forClass(AppendEventRequest.class);
        verify(appendService).append(captor.capture());
        assertThat(captor.getValue().sourceTimestamp()).isNull();
    }

    @Test
    void acceptsOffsetBearingTimestampAndConvertsToEquivalentUtcInstant() throws Exception {
        // +02:00 offset: 04:00:00.123+02:00 is exactly 02:00:00.123Z
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {},
                    "sourceTimestamp": "2026-10-15T04:00:00.123+02:00"
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated());

        ArgumentCaptor<AppendEventRequest> captor = ArgumentCaptor.forClass(AppendEventRequest.class);
        verify(appendService).append(captor.capture());
        assertThat(captor.getValue().sourceTimestamp()).isEqualTo(Instant.parse("2026-10-15T02:00:00.123Z"));
    }

    @Test
    void permitsLargeIntegerAsStringInPayload() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {
                        "balance": "9007199254740993"
                    }
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated());
    }

    // -------------------------------------------------------------------------
    // Request Validation Errors (HTTP 400 Bad Request)
    // -------------------------------------------------------------------------

    @Test
    void rejectsMissingEventType() throws Exception {
        String json = """
                {
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("eventType must not be null or blank"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsBlankActorId() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "   ",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("actorId must not be null or blank"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsNullPayload() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": null
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("payload must not be null"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsNonObjectPayload() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": [1, 2, 3]
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("payload must be a JSON object"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsMalformedJson() throws Exception {
        String malformedJson = "{ \"eventType\": \"USER_LOGIN\", unclosed ";

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(malformedJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Malformed JSON request body"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsInvalidSourceTimestamp() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {},
                    "sourceTimestamp": "not-a-timestamp"
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid timestamp format for sourceTimestamp; must be valid ISO-8601 timestamp"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsUnsafeIntegerInPayload() throws Exception {
        when(appendService.append(any(AppendEventRequest.class)))
                .thenThrow(new IllegalArgumentException(
                        "Integer 9007199254740993 is outside safe IEEE-754 range [-(2^53-1), 2^53-1]; encode as string per RFC 8785 Appendix D / RFC 7493"));

        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {
                        "amount": 9007199254740993
                    }
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Integer 9007199254740993 is outside safe IEEE-754 range [-(2^53-1), 2^53-1]; encode as string per RFC 8785 Appendix D / RFC 7493"));
    }

    // -------------------------------------------------------------------------
    // Duplicate Key Detection (RFC 8785 §3.2.3 & RFC 7493 §2.3)
    // -------------------------------------------------------------------------

    @Test
    void rejectsDuplicateTopLevelProperty() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "first",
                    "actorId": "second",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Duplicate JSON property: 'actorId'"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsDuplicateNestedPayloadProperty() throws Exception {
        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {
                        "sub": "first",
                        "sub": "second"
                    }
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Duplicate JSON property: 'sub'"));

        verify(appendService, never()).append(any());
    }

    // -------------------------------------------------------------------------
    // Request Body Size Enforcement (HTTP 413 Payload Too Large)
    // -------------------------------------------------------------------------

    @Test
    void rejectsDeclaredOversizedRequestBodyWith413() throws Exception {
        // Body exceeding 1 MiB (1,048,576 bytes)
        int size = 1024 * 1024 + 100;
        String largePadding = "a".repeat(size);
        String json = "{\"eventType\":\"LOGIN\",\"actorId\":\"a\",\"resourceType\":\"R\",\"resourceId\":\"1\",\"payload\":{\"pad\":\""
                + largePadding + "\"}}";

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.status").value(413))
                .andExpect(jsonPath("$.error").value("Payload Too Large"))
                .andExpect(jsonPath("$.message").value("Request payload exceeds maximum allowed size of 1048576 bytes"));

        verify(appendService, never()).append(any());
    }

    @Test
    void rejectsChunkedOversizedRequestBodyWith413() throws Exception {
        int size = 1024 * 1024 + 100;
        String largePadding = "a".repeat(size);
        String json = "{\"eventType\":\"LOGIN\",\"actorId\":\"a\",\"resourceType\":\"R\",\"resourceId\":\"1\",\"payload\":{\"pad\":\""
                + largePadding + "\"}}";

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.TRANSFER_ENCODING, "chunked")
                        .content(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.status").value(413))
                .andExpect(jsonPath("$.error").value("Payload Too Large"))
                .andExpect(jsonPath("$.message").value("Request payload exceeds maximum allowed size of 1048576 bytes"));

        verify(appendService, never()).append(any());
    }

    // -------------------------------------------------------------------------
    // Error Sanitization and Status Codes
    // -------------------------------------------------------------------------

    @Test
    void returns503WithRetryAfterOnChainHeadLockContention() throws Exception {
        when(appendService.append(any(AppendEventRequest.class)))
                .thenThrow(new CannotAcquireLockException("Lock wait timeout exceeded (55P03)"));

        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "1"))
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(jsonPath("$.message").value("Temporary lock contention on the audit chain head. Please retry."));
    }

    @Test
    void sanitizesDatabaseErrorWithoutLeakingInternalDetailsOrSql() throws Exception {
        when(appendService.append(any(AppendEventRequest.class)))
                .thenThrow(new DataIntegrityViolationException(
                        "ERROR: duplicate key value violates unique constraint audit_event_event_id_key\n"
                        + "Detail: Key (event_id)=(...) already exists in table audit_event."));

        String json = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "actor-123",
                    "resourceType": "ACCOUNT",
                    "resourceId": "account-456",
                    "payload": {}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.error").value("Internal Server Error"))
                .andExpect(jsonPath("$.message").value("An internal database error occurred while recording the audit event."))
                // Assert no SQL, constraint, or table names leak
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("SQL"))))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("constraint"))))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("audit_event"))));
    }

    @Test
    void rejectsUnsupportedMediaType() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("hello"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.status").value(415))
                .andExpect(jsonPath("$.message").value("Content-Type must be application/json"));
    }
}
