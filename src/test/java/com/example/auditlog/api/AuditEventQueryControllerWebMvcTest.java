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
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.query.AuditQueryCriteria;
import com.example.auditlog.query.AuditQueryService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import com.example.auditlog.security.SecurityConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@code GET /audit/events} validating HTTP query contracts,
 * parameter mapping, pagination defaults, input validation, error handling, and response schema.
 */
@WebMvcTest(AuditEventController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class, SecurityConfiguration.class})
@WithMockUser(username = "test-auditor", roles = "AUDITOR")
class AuditEventQueryControllerWebMvcTest {

    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final String SOURCE_TIMESTAMP = "2026-10-15T02:29:59.000Z";
    private static final String RECORDED_AT = "2026-10-15T02:30:00.456Z";
    private static final String CONTENT_HASH = "4adef4d4355b8181195edbafb7dd255548eadf027fcc289c01b2cf5666530b26";
    private static final String PREVIOUS_HASH = "0".repeat(64);
    private static final String RECORD_HASH = "d4fdc27004f4d0ab21f89b9259ea15175f0a7b85fcc6bfa2c0bb1713c573e00e";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuditAppendService appendService;

    @MockBean
    private AuditQueryService queryService;

    @Test
    @DisplayName("GET /audit/events with default parameters queries first page with size 20")
    void testGetEvents_defaultParameters() throws Exception {
        AuditEventDto event = new AuditEventDto(
                1L,
                EVENT_ID,
                "user.login",
                "usr_123",
                "session",
                "sess_abc",
                objectMapper.readTree("{\"ip\":\"10.0.0.1\"}"),
                SOURCE_TIMESTAMP,
                RECORDED_AT,
                "1",
                CONTENT_HASH,
                PREVIOUS_HASH,
                RECORD_HASH);

        AuditPageResponse<AuditEventDto> pageResponse = new AuditPageResponse<>(
                List.of(event), 0, 20, 1L, 1, true, true);

        when(queryService.query(any(AuditQueryCriteria.class))).thenReturn(pageResponse);

        mockMvc.perform(get("/audit/events")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.first").value(true))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.events[0].eventId").value(EVENT_ID.toString()))
                .andExpect(jsonPath("$.events[0].sequenceNo").value(1))
                .andExpect(jsonPath("$.events[0].eventType").value("user.login"))
                .andExpect(jsonPath("$.events[0].actorId").value("usr_123"))
                .andExpect(jsonPath("$.events[0].resourceType").value("session"))
                .andExpect(jsonPath("$.events[0].resourceId").value("sess_abc"))
                .andExpect(jsonPath("$.events[0].payload.ip").value("10.0.0.1"))
                .andExpect(jsonPath("$.events[0].sourceTimestamp").value(SOURCE_TIMESTAMP))
                .andExpect(jsonPath("$.events[0].recordedAt").value(RECORDED_AT))
                .andExpect(jsonPath("$.events[0].canonicalizationVersion").value(1))
                .andExpect(jsonPath("$.events[0].contentHash").value(CONTENT_HASH))
                .andExpect(jsonPath("$.events[0].previousHash").value(PREVIOUS_HASH))
                .andExpect(jsonPath("$.events[0].recordHash").value(RECORD_HASH));

        ArgumentCaptor<AuditQueryCriteria> captor = ArgumentCaptor.forClass(AuditQueryCriteria.class);
        verify(queryService).query(captor.capture());
        AuditQueryCriteria criteria = captor.getValue();
        assertThat(criteria.page()).isEqualTo(0);
        assertThat(criteria.size()).isEqualTo(20);
        assertThat(criteria.actorId()).isNull();
        assertThat(criteria.resourceType()).isNull();
        assertThat(criteria.resourceId()).isNull();
        assertThat(criteria.eventType()).isNull();
        assertThat(criteria.from()).isNull();
        assertThat(criteria.to()).isNull();

        verify(appendService, never()).append(any());
    }

    @Test
    @DisplayName("GET /audit/events binds all filter criteria and pagination parameters correctly")
    void testGetEvents_allFiltersProvided() throws Exception {
        AuditPageResponse<AuditEventDto> emptyPage = new AuditPageResponse<>(
                List.of(), 3, 50, 0L, 0, false, true);

        when(queryService.query(any(AuditQueryCriteria.class))).thenReturn(emptyPage);

        mockMvc.perform(get("/audit/events")
                        .param("actorId", "usr_admin")
                        .param("resourceType", "document")
                        .param("resourceId", "doc_789")
                        .param("eventType", "document.create")
                        .param("from", "2026-10-15T00:00:00Z")
                        .param("to", "2026-10-15T12:00:00Z")
                        .param("page", "3")
                        .param("size", "50")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(3))
                .andExpect(jsonPath("$.size").value(50))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0))
                .andExpect(jsonPath("$.events").isEmpty());

        ArgumentCaptor<AuditQueryCriteria> captor = ArgumentCaptor.forClass(AuditQueryCriteria.class);
        verify(queryService).query(captor.capture());
        AuditQueryCriteria criteria = captor.getValue();
        assertThat(criteria.actorId()).isEqualTo("usr_admin");
        assertThat(criteria.resourceType()).isEqualTo("document");
        assertThat(criteria.resourceId()).isEqualTo("doc_789");
        assertThat(criteria.eventType()).isEqualTo("document.create");
        assertThat(criteria.from()).isEqualTo(Instant.parse("2026-10-15T00:00:00Z"));
        assertThat(criteria.to()).isEqualTo(Instant.parse("2026-10-15T12:00:00Z"));
        assertThat(criteria.page()).isEqualTo(3);
        assertThat(criteria.size()).isEqualTo(50);
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for negative page")
    void testGetEvents_negativePage() throws Exception {
        mockMvc.perform(get("/audit/events").param("page", "-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("page must not be negative"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for size less than 1")
    void testGetEvents_sizeZero() throws Exception {
        mockMvc.perform(get("/audit/events").param("size", "0"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("size must be between 1 and 100"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for size greater than 100")
    void testGetEvents_sizeGreaterThan100() throws Exception {
        mockMvc.perform(get("/audit/events").param("size", "101"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("size must be between 1 and 100"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for blank filter parameters")
    void testGetEvents_blankFilters() throws Exception {
        mockMvc.perform(get("/audit/events").param("actorId", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("actorId must not be blank if provided"));

        mockMvc.perform(get("/audit/events").param("resourceType", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("resourceType must not be blank if provided"));

        mockMvc.perform(get("/audit/events").param("resourceId", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("resourceId must not be blank if provided"));

        mockMvc.perform(get("/audit/events").param("eventType", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("eventType must not be blank if provided"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for invalid ISO-8601 timestamp in from or to")
    void testGetEvents_invalidTimestamp() throws Exception {
        mockMvc.perform(get("/audit/events").param("from", "invalid-timestamp"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid timestamp format for 'from'; must be valid ISO-8601 timestamp"));

        mockMvc.perform(get("/audit/events").param("to", "2026/10/15 12:00:00"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid timestamp format for 'to'; must be valid ISO-8601 timestamp"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 when from is after to")
    void testGetEvents_fromAfterTo() throws Exception {
        mockMvc.perform(get("/audit/events")
                        .param("from", "2026-10-15T12:00:01Z")
                        .param("to", "2026-10-15T12:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("'from' timestamp must not be after 'to' timestamp"));

        verify(queryService, never()).query(any());
    }

    @Test
    @DisplayName("GET /audit/events returns 400 for non-integer page or size parameter")
    void testGetEvents_typeMismatch() throws Exception {
        mockMvc.perform(get("/audit/events").param("page", "not-a-number"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid value for parameter 'page'"));

        mockMvc.perform(get("/audit/events").param("size", "big"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid value for parameter 'size'"));

        verify(queryService, never()).query(any());
    }
}
