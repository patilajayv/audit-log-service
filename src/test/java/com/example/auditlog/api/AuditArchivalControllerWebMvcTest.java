package com.example.auditlog.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.archival.ArchiveEventResult;
import com.example.auditlog.archival.AuditArchivalService;
import com.example.auditlog.hashing.AuditHashService;
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
 * WebMvc slice tests for {@link AuditArchivalController} validating HTTP contracts,
 * JSON serialization, and sanitized error responses.
 */
@WebMvcTest(AuditArchivalController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-writer", roles = "AUDIT_WRITER")
class AuditArchivalControllerWebMvcTest {

    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant ARCHIVED_AT = Instant.parse("2026-10-15T10:00:00.000Z");

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuditArchivalService archivalService;

    @Test
    @DisplayName("POST /audit/archive/{eventId} returns 200 OK with archive result")
    void testArchiveSingleEvent_success() throws Exception {
        ArchiveEventResult result = new ArchiveEventResult(EVENT_ID, ARCHIVED_AT, "retention-policy-1", "");
        when(archivalService.archive(eq(EVENT_ID), eq("retention-policy-1"))).thenReturn(result);

        mockMvc.perform(post("/audit/archive/" + EVENT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyRef\": \"retention-policy-1\"}")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.eventId").value(EVENT_ID.toString()))
                .andExpect(jsonPath("$.archivedAt").value(ARCHIVED_AT.toString()))
                .andExpect(jsonPath("$.policyRef").value("retention-policy-1"))
                .andExpect(jsonPath("$.archiveLocation").value(""));
    }

    @Test
    @DisplayName("POST /audit/archive/{eventId} returns 404 NOT_FOUND when event does not exist")
    void testArchiveSingleEvent_notFound() throws Exception {
        when(archivalService.archive(eq(EVENT_ID), any()))
                .thenThrow(new AuditEventNotFoundException(EVENT_ID));

        mockMvc.perform(post("/audit/archive/" + EVENT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyRef\": \"retention-policy-1\"}")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Audit event not found: " + EVENT_ID));
    }

    @Test
    @DisplayName("POST /audit/archive/{eventId} returns 400 BAD_REQUEST when policyRef is blank")
    void testArchiveSingleEvent_blankPolicyRef() throws Exception {
        mockMvc.perform(post("/audit/archive/" + EVENT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyRef\": \"   \"}")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("policyRef must not be blank"));
    }

    @Test
    @DisplayName("POST /audit/archive/eligible returns 200 OK with count of archived events")
    void testArchiveEligible_success() throws Exception {
        when(archivalService.archiveEligible("default-90d")).thenReturn(42);

        mockMvc.perform(post("/audit/archive/eligible")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyRef\": \"default-90d\"}")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.archivedCount").value(42));
    }

    @Test
    @DisplayName("POST /audit/archive/eligible returns 400 BAD_REQUEST when policyRef is blank")
    void testArchiveEligible_blankPolicyRef() throws Exception {
        mockMvc.perform(post("/audit/archive/eligible")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyRef\": \"\"}")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("policyRef must not be blank"));
    }
}
