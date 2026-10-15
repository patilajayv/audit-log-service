package com.example.auditlog.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.compliance.AuditComplianceService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.export.ExportChainHeadDto;
import com.example.auditlog.export.ExportEventDto;
import com.example.auditlog.export.ExportFilterDto;
import com.example.auditlog.export.ExportSummaryDto;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.security.SecurityConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@link AuditComplianceController} validating HTTP contracts,
 * parameter validations, fail-closed error translation, and response structures.
 */
@WebMvcTest(AuditComplianceController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-regulator", roles = "REGULATOR")
class AuditComplianceControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuditComplianceService complianceService;

    @Test
    @DisplayName("GET /audit/compliance/account-access with valid accountId returns 200 OK")
    void queryWithValidAccountIdReturns200() throws Exception {
        UUID eventId = UUID.randomUUID();
        AuditEventDto dto = new AuditEventDto(
                1L,
                eventId,
                "ACCOUNT_VIEWED",
                "advisor-42",
                "ACCOUNT",
                "ACC-12345",
                objectMapper.readTree("{\"accessType\":\"VIEW\",\"actorRole\":\"WEALTH_ADVISOR\"}"),
                "2026-10-15T12:00:00.000Z",
                "2026-10-15T12:00:01.000Z",
                "JCS-1",
                "chash1",
                "phash1",
                "rhash1",
                null);

        AuditPageResponse<AuditEventDto> pageResponse = AuditPageResponse.of(
                List.of(dto), 0, 20, 1L);

        when(complianceService.queryAccountAccess(
                eq("ACC-12345"), any(), any(), any(), any(), eq(0), eq(20), eq(true), any(), any()))
                .thenReturn(pageResponse);

        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("accountId", "ACC-12345")
                        .header("X-Correlation-Id", "corr-test-01")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.events[0].sequenceNo").value(1))
                .andExpect(jsonPath("$.events[0].eventId").value(eventId.toString()))
                .andExpect(jsonPath("$.events[0].resourceType").value("ACCOUNT"))
                .andExpect(jsonPath("$.events[0].resourceId").value("ACC-12345"))
                .andExpect(jsonPath("$.events[0].eventType").value("ACCOUNT_VIEWED"))
                .andExpect(jsonPath("$.events[0].payload.accessType").value("VIEW"));
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access with missing accountId returns 400 Bad Request")
    void queryWithMissingAccountIdReturns400() throws Exception {
        mockMvc.perform(get("/audit/compliance/account-access")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'accountId' is required and must not be blank"));

        verify(complianceService, never()).queryAccountAccess(any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access with blank accountId returns 400 Bad Request")
    void queryWithBlankAccountIdReturns400() throws Exception {
        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("accountId", "   ")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'accountId' is required and must not be blank"));

        verify(complianceService, never()).queryAccountAccess(any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access/export with valid accountId returns 200 OK and bundle")
    void exportWithValidAccountIdReturns200() throws Exception {
        UUID exportId = UUID.randomUUID();
        ExportBundleDto mockBundle = new ExportBundleDto(
                "1.0",
                exportId,
                "2026-10-15T14:00:00.000Z",
                new ExportFilterDto("RESOURCE_ID", "ACC-12345", true),
                new ExportChainHeadDto(5L, "headhash5"),
                new ExportSummaryDto(1L, 3L, 3L, 4L),
                List.of(new ExportEventDto(
                        3L,
                        UUID.randomUUID(),
                        "ACCOUNT_VIEWED",
                        "teller-1",
                        "ACCOUNT",
                        "ACC-12345",
                        objectMapper.readTree("{\"accessType\":\"VIEW\"}"),
                        "2026-10-15T12:00:00.000Z",
                        "2026-10-15T12:00:01.000Z",
                        "JCS-1",
                        "chash3",
                        "phash3",
                        "rhash3",
                        null)),
                Collections.emptyList());

        when(complianceService.exportAccountAccess(eq("ACC-12345"), eq(true), any(), any()))
                .thenReturn(mockBundle);

        mockMvc.perform(get("/audit/compliance/account-access/export")
                        .param("accountId", "ACC-12345")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bundleVersion").value("1.0"))
                .andExpect(jsonPath("$.filter.filterType").value("RESOURCE_ID"))
                .andExpect(jsonPath("$.filter.filterValue").value("ACC-12345"))
                .andExpect(jsonPath("$.summary.matchedEventsCount").value(1))
                .andExpect(jsonPath("$.events[0].sequenceNo").value(3))
                .andExpect(jsonPath("$.events[0].resourceType").value("ACCOUNT"))
                .andExpect(jsonPath("$.events[0].resourceId").value("ACC-12345"));
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access/export with missing accountId returns 400 Bad Request")
    void exportWithMissingAccountIdReturns400() throws Exception {
        mockMvc.perform(get("/audit/compliance/account-access/export")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'accountId' is required and must not be blank"));

        verify(complianceService, never()).exportAccountAccess(any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access fail-closed on lock contention returns 503 with Retry-After: 1")
    void queryFailClosedLockContentionReturns503() throws Exception {
        when(complianceService.queryAccountAccess(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new CannotAcquireLockException("Could not acquire lock on chain head"));

        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("accountId", "ACC-12345")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "1"))
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(jsonPath("$.message").value("Temporary lock contention on the audit chain head. Please retry."));
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access fail-closed on database error returns sanitized 500")
    void queryFailClosedDatabaseErrorReturns500() throws Exception {
        when(complianceService.queryAccountAccess(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new DataIntegrityViolationException("Database constraint violation in audit_event"));

        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("accountId", "ACC-12345")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").value("An internal database error occurred while recording the audit event."));
    }
}
