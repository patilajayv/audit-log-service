package com.example.auditlog.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.export.AuditExportService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.export.ExportChainHeadDto;
import com.example.auditlog.export.ExportEventDto;
import com.example.auditlog.export.ExportFilterCriteria;
import com.example.auditlog.export.ExportFilterDto;
import com.example.auditlog.export.ExportSummaryDto;
import com.example.auditlog.export.ExportWitnessDto;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.security.SecurityConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@code GET /audit/exports} validating HTTP contract,
 * parameter validation (mutual exclusivity, blank checks), error handling, and response schema.
 */
@WebMvcTest(AuditExportController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-auditor", roles = "AUDITOR")
class AuditExportControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuditExportService exportService;

    @Test
    @DisplayName("GET /audit/exports with valid actorId returns 200 OK and valid bundle schema")
    void exportWithValidActorIdReturns200() throws Exception {
        UUID exportId = UUID.randomUUID();
        ExportBundleDto mockBundle = new ExportBundleDto(
                "1.0",
                exportId,
                "2026-10-15T14:00:00.000Z",
                new ExportFilterDto("ACTOR_ID", "user-123", true),
                new ExportChainHeadDto(10L, "hash10"),
                new ExportSummaryDto(1L, 2L, 2L, 9L),
                List.of(new ExportEventDto(
                        2L,
                        UUID.randomUUID(),
                        "ORDER_PLACED",
                        "user-123",
                        "ACCOUNT",
                        "acc-456",
                        objectMapper.createObjectNode().put("amount", 100),
                        null,
                        "2026-10-15T13:59:00.000Z",
                        "JCS-1",
                        "contentHash2",
                        "prevHash2",
                        "recordHash2",
                        null
                )),
                List.of(new ExportWitnessDto(1L, "0".repeat(64), "contentHash1", "recordHash1"))
        );

        when(exportService.exportBundle(any(ExportFilterCriteria.class))).thenReturn(mockBundle);

        mockMvc.perform(get("/audit/exports")
                        .param("actorId", "user-123")
                        .header("X-Correlation-Id", "corr-test-1")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.bundleVersion").value("1.0"))
                .andExpect(jsonPath("$.exportId").value(exportId.toString()))
                .andExpect(jsonPath("$.exportedAt").value("2026-10-15T14:00:00.000Z"))
                .andExpect(jsonPath("$.filter.filterType").value("ACTOR_ID"))
                .andExpect(jsonPath("$.filter.filterValue").value("user-123"))
                .andExpect(jsonPath("$.filter.includeArchived").value(true))
                .andExpect(jsonPath("$.chainHead.sequenceNo").value(10))
                .andExpect(jsonPath("$.chainHead.recordHash").value("hash10"))
                .andExpect(jsonPath("$.summary.matchedEventsCount").value(1))
                .andExpect(jsonPath("$.summary.witnessCount").value(9))
                .andExpect(jsonPath("$.events[0].sequenceNo").value(2))
                .andExpect(jsonPath("$.events[0].actorId").value("user-123"))
                .andExpect(jsonPath("$.witnesses[0].sequenceNo").value(1));

        ArgumentCaptor<ExportFilterCriteria> captor = ArgumentCaptor.forClass(ExportFilterCriteria.class);
        verify(exportService).exportBundle(captor.capture());
        assertThat(captor.getValue().filterType()).isEqualTo(ExportFilterCriteria.FilterType.ACTOR_ID);
        assertThat(captor.getValue().filterValue()).isEqualTo("user-123");
        assertThat(captor.getValue().includeArchived()).isTrue();
    }

    @Test
    @DisplayName("GET /audit/exports with valid resourceId returns 200 OK")
    void exportWithValidResourceIdReturns200() throws Exception {
        UUID exportId = UUID.randomUUID();
        ExportBundleDto mockBundle = new ExportBundleDto(
                "1.0",
                exportId,
                "2026-10-15T14:00:00.000Z",
                new ExportFilterDto("RESOURCE_ID", "order-999", false),
                new ExportChainHeadDto(5L, "hash5"),
                new ExportSummaryDto(0L, null, null, 5L),
                Collections.emptyList(),
                Collections.emptyList()
        );

        when(exportService.exportBundle(any(ExportFilterCriteria.class))).thenReturn(mockBundle);

        mockMvc.perform(get("/audit/exports")
                        .param("resourceId", "order-999")
                        .param("includeArchived", "false")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.filter.filterType").value("RESOURCE_ID"))
                .andExpect(jsonPath("$.filter.filterValue").value("order-999"))
                .andExpect(jsonPath("$.filter.includeArchived").value(false));

        ArgumentCaptor<ExportFilterCriteria> captor = ArgumentCaptor.forClass(ExportFilterCriteria.class);
        verify(exportService).exportBundle(captor.capture());
        assertThat(captor.getValue().filterType()).isEqualTo(ExportFilterCriteria.FilterType.RESOURCE_ID);
        assertThat(captor.getValue().filterValue()).isEqualTo("order-999");
        assertThat(captor.getValue().includeArchived()).isFalse();
    }

    @Test
    @DisplayName("GET /audit/exports with both actorId and resourceId returns 400 Bad Request")
    void exportWithBothFiltersReturns400() throws Exception {
        mockMvc.perform(get("/audit/exports")
                        .param("actorId", "user-123")
                        .param("resourceId", "order-999")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Parameters 'actorId' and 'resourceId' are mutually exclusive; provide exactly one"));

        verify(exportService, never()).exportBundle(any());
    }

    @Test
    @DisplayName("GET /audit/exports with neither actorId nor resourceId returns 400 Bad Request")
    void exportWithNeitherFilterReturns400() throws Exception {
        mockMvc.perform(get("/audit/exports")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Either 'actorId' or 'resourceId' must be provided"));

        verify(exportService, never()).exportBundle(any());
    }

    @Test
    @DisplayName("GET /audit/exports with blank actorId returns 400 Bad Request")
    void exportWithBlankActorIdReturns400() throws Exception {
        mockMvc.perform(get("/audit/exports")
                        .param("actorId", "   ")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'actorId' must not be blank"));

        verify(exportService, never()).exportBundle(any());
    }

    @Test
    @DisplayName("GET /audit/exports with blank resourceId returns 400 Bad Request")
    void exportWithBlankResourceIdReturns400() throws Exception {
        mockMvc.perform(get("/audit/exports")
                        .param("resourceId", "\t  \n")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'resourceId' must not be blank"));

        verify(exportService, never()).exportBundle(any());
    }

    @Test
    @DisplayName("GET /audit/exports returning PayloadTooLargeException yields 413 Payload Too Large")
    void exportPayloadTooLargeReturns413() throws Exception {
        when(exportService.exportBundle(any(ExportFilterCriteria.class)))
                .thenThrow(new PayloadTooLargeException("Export exceeds maximum supported matching events limit of 1000. Please refine your filter criteria."));

        mockMvc.perform(get("/audit/exports")
                        .param("actorId", "user-123")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.status").value(413))
                .andExpect(jsonPath("$.error").value("Payload Too Large"))
                .andExpect(jsonPath("$.message").value("Export exceeds maximum supported matching events limit of 1000. Please refine your filter criteria."));
    }
}
