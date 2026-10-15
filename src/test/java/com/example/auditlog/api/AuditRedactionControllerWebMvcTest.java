package com.example.auditlog.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.redaction.AuditRedactionService;
import com.example.auditlog.redaction.RedactionKeyDestructionException;
import com.example.auditlog.redaction.RedactionRequest;
import com.example.auditlog.redaction.RedactionResult;
import com.example.auditlog.security.SecurityConfiguration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@link AuditRedactionController} validating HTTP contracts,
 * input validation, JSON serialization, and sanitized error responses.
 */
@WebMvcTest(AuditRedactionController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-writer", roles = "AUDIT_WRITER")
class AuditRedactionControllerWebMvcTest {

    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant REDACTED_AT = Instant.parse("2026-10-15T12:00:00.000Z");

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuditRedactionService redactionService;

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact returns 200 OK with redaction result")
    void testRedact_success() throws Exception {
        RedactionResult result = new RedactionResult(
                EVENT_ID,
                "accountNumber",
                REDACTED_AT,
                "GDPR_ARTICLE_17",
                "compliance-officer-1",
                "CRYPTO_SHREDDED",
                "COMPLETED",
                42L);

        when(redactionService.redact(eq(EVENT_ID), any(RedactionRequest.class))).thenReturn(result);

        mockMvc.perform(post("/audit/events/" + EVENT_ID + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fieldPath": "accountNumber",
                                  "reason": "GDPR_ARTICLE_17",
                                  "requestedBy": "compliance-officer-1"
                                }
                                """)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.eventId").value(EVENT_ID.toString()))
                .andExpect(jsonPath("$.fieldPath").value("accountNumber"))
                .andExpect(jsonPath("$.redactedAt").value(REDACTED_AT.toString()))
                .andExpect(jsonPath("$.reason").value("GDPR_ARTICLE_17"))
                .andExpect(jsonPath("$.requestedBy").value("compliance-officer-1"))
                .andExpect(jsonPath("$.redactionType").value("CRYPTO_SHREDDED"))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.metaAuditSequenceNo").value(42));
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact returns 404 NOT_FOUND when event does not exist")
    void testRedact_notFound() throws Exception {
        when(redactionService.redact(eq(EVENT_ID), any(RedactionRequest.class)))
                .thenThrow(new AuditEventNotFoundException(EVENT_ID));

        mockMvc.perform(post("/audit/events/" + EVENT_ID + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fieldPath": "accountNumber",
                                  "reason": "GDPR_ARTICLE_17",
                                  "requestedBy": "compliance-officer-1"
                                }
                                """)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Audit event not found: " + EVENT_ID));
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact returns 400 BAD_REQUEST when fieldPath is not in payload")
    void testRedact_fieldNotFound() throws Exception {
        when(redactionService.redact(eq(EVENT_ID), any(RedactionRequest.class)))
                .thenThrow(new IllegalArgumentException("Field path 'nonExistent' not found in event payload"));

        mockMvc.perform(post("/audit/events/" + EVENT_ID + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fieldPath": "nonExistent",
                                  "reason": "GDPR_ARTICLE_17",
                                  "requestedBy": "compliance-officer-1"
                                }
                                """)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Field path 'nonExistent' not found in event payload"));
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact returns 400 BAD_REQUEST when validation fails")
    void testRedact_validationFailure() throws Exception {
        mockMvc.perform(post("/audit/events/" + EVENT_ID + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fieldPath": "",
                                  "reason": "   ",
                                  "requestedBy": ""
                                }
                                """)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"));
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact returns 502 BAD_GATEWAY on key destruction failure")
    void testRedact_keyDestructionFailure() throws Exception {
        when(redactionService.redact(eq(EVENT_ID), any(RedactionRequest.class)))
                .thenThrow(new RedactionKeyDestructionException("dek-123", new RuntimeException("KMS unavailable")));

        mockMvc.perform(post("/audit/events/" + EVENT_ID + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fieldPath": "accountNumber",
                                  "reason": "GDPR_ARTICLE_17",
                                  "requestedBy": "compliance-officer-1"
                                }
                                """)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.status").value(502))
                .andExpect(jsonPath("$.error").value("Bad Gateway"))
                .andExpect(jsonPath("$.message").value("Key destruction failed in Key Management Service"));
    }

    @Test
    @DisplayName("GET /audit/events/{eventId}/redact is rejected by default deny (403 Forbidden)")
    void testRedact_methodNotAllowed() throws Exception {
        mockMvc.perform(get("/audit/events/" + EVENT_ID + "/redact")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }
}
