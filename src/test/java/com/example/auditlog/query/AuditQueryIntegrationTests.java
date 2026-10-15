package com.example.auditlog.query;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.archival.AuditArchivalService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * End-to-end integration tests for {@code GET /audit/events} against PostgreSQL 16
 * using Testcontainers, Flyway, embedded web server, and {@link TestRestTemplate}.
 *
 * <p>Validates pagination, filtering, determinism, boundary handling, sanitized errors,
 * and read-only behavior.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditQueryIntegrationTests {

    private static final ParameterizedTypeReference<AuditPageResponse<AuditEventDto>> EVENT_PAGE_TYPE =
            new ParameterizedTypeReference<>() {};

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) throws SQLException {
        POSTGRES.start();
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE ROLE audit_app LOGIN PASSWORD 'test-password' "
                    + "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT");
        }
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.flyway.clean-disabled", () -> "false");
    }

    @Autowired
    private TestRestTemplate rawRestTemplate;

    private TestRestTemplate restTemplate;

    @Autowired
    private AuditAppendService appendService;

    @Autowired
    private AuditArchivalService archivalService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void cleanAndMigrate() {
        this.restTemplate = rawRestTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        flyway.clean();
        flyway.migrate();
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Test
    @DisplayName("Query against empty database returns empty page")
    void testQueryEmptyDatabase() {
        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.events()).isEmpty();
        assertThat(body.page()).isZero();
        assertThat(body.size()).isEqualTo(20);
        assertThat(body.totalElements()).isZero();
        assertThat(body.totalPages()).isZero();
        assertThat(body.first()).isTrue();
        assertThat(body.last()).isTrue();
    }

    @Test
    @DisplayName("Query all events with pagination validates deterministic sequence_no ASC ordering without duplicate or skipped events")
    void testQueryPaginationDeterministicOrdering() throws Exception {
        int totalEvents = 15;
        List<AppendEventResult> appended = seedEvents(totalEvents);

        int pageSize = 5;
        List<Long> gatheredSequences = new ArrayList<>();

        for (int p = 0; p < 3; p++) {
            ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                    "/audit/events?page=" + p + "&size=" + pageSize,
                    HttpMethod.GET,
                    new HttpEntity<>(jsonHeaders()),
                    new ParameterizedTypeReference<>() {});

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            AuditPageResponse<AuditEventDto> body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.page()).isEqualTo(p);
            assertThat(body.size()).isEqualTo(pageSize);
            assertThat(body.totalElements()).isEqualTo(15L);
            assertThat(body.totalPages()).isEqualTo(3);
            assertThat(body.first()).isEqualTo(p == 0);
            assertThat(body.last()).isEqualTo(p == 2);
            assertThat(body.events()).hasSize(pageSize);

            for (AuditEventDto dto : body.events()) {
                gatheredSequences.add(dto.sequenceNo());
                assertThat(dto.eventId()).isNotNull();
                assertThat(dto.recordHash()).isNotBlank();
                assertThat(dto.contentHash()).isNotBlank();
                assertThat(dto.previousHash()).isNotBlank();
                assertThat(dto.recordedAt()).isNotBlank();
                assertThat(dto.sourceTimestamp()).isNotBlank();
                assertThat(dto.canonicalizationVersion()).isEqualTo("JCS-1");
            }
        }

        // Must be strictly contiguous 1..15 with no duplicates or skips
        assertThat(gatheredSequences).containsExactly(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L, 11L, 12L, 13L, 14L, 15L);
    }

    @Test
    @DisplayName("Filter by actorId returns only matching events with consistent count")
    void testFilterByActorId() throws Exception {
        seedEvents(10); // user-0 to user-9

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?actorId=user-3",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.totalElements()).isEqualTo(1L);
        assertThat(body.events()).hasSize(1);
        assertThat(body.events().get(0).actorId()).isEqualTo("user-3");
        assertThat(body.events().get(0).sequenceNo()).isEqualTo(4L);
    }

    @Test
    @DisplayName("Filter by resourceType and resourceId returns exact match")
    void testFilterByResource() throws Exception {
        seedEvents(10);

        // Filter by resourceType alone
        ResponseEntity<AuditPageResponse<AuditEventDto>> typeResponse = restTemplate.exchange(
                "/audit/events?resourceType=order",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(typeResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> typeBody = typeResponse.getBody();
        assertThat(typeBody).isNotNull();
        // Even indices get resourceType "order" (0, 2, 4, 6, 8 -> 5 events)
        assertThat(typeBody.totalElements()).isEqualTo(5L);
        assertThat(typeBody.events()).allMatch(e -> "order".equals(e.resourceType()));

        // Filter by resourceType and resourceId
        ResponseEntity<AuditPageResponse<AuditEventDto>> exactResponse = restTemplate.exchange(
                "/audit/events?resourceType=order&resourceId=res-4",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(exactResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> exactBody = exactResponse.getBody();
        assertThat(exactBody).isNotNull();
        assertThat(exactBody.totalElements()).isEqualTo(1L);
        assertThat(exactBody.events().get(0).resourceType()).isEqualTo("order");
        assertThat(exactBody.events().get(0).resourceId()).isEqualTo("res-4");
        assertThat(exactBody.events().get(0).sequenceNo()).isEqualTo(5L);
    }

    @Test
    @DisplayName("Filter by eventType returns only matching event types")
    void testFilterByEventType() throws Exception {
        seedEvents(10);

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?eventType=order.created",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        // Even indices get "order.created" -> 5 events
        assertThat(body.totalElements()).isEqualTo(5L);
        assertThat(body.events()).allMatch(e -> "order.created".equals(e.eventType()));
    }

    @Test
    @DisplayName("Filter by recorded_at timestamp range includes boundaries")
    void testFilterByTimestampRange() throws Exception {
        List<AppendEventResult> seeded = seedEvents(6);

        // Events 2, 3, 4 (0-indexed: 1, 2, 3)
        String from = seeded.get(1).recordedAt().toString();
        String to = seeded.get(3).recordedAt().toString();

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?from=" + from + "&to=" + to,
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.totalElements()).isEqualTo(3L);
        assertThat(body.events()).hasSize(3);
        assertThat(body.events().get(0).sequenceNo()).isEqualTo(2L);
        assertThat(body.events().get(1).sequenceNo()).isEqualTo(3L);
        assertThat(body.events().get(2).sequenceNo()).isEqualTo(4L);
    }

    @Test
    @DisplayName("Filter with multiple combined criteria returns intersection")
    void testCombinedFilterCriteria() throws Exception {
        seedEvents(10);

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?actorId=user-2&eventType=order.created&resourceType=order",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.totalElements()).isEqualTo(1L);
        assertThat(body.events().get(0).sequenceNo()).isEqualTo(3L);
        assertThat(body.events().get(0).actorId()).isEqualTo("user-2");
        assertThat(body.events().get(0).eventType()).isEqualTo("order.created");
        assertThat(body.events().get(0).resourceType()).isEqualTo("order");
    }

    @Test
    @DisplayName("Filter matching no records returns empty page with totalElements 0")
    void testFilterNoMatches() throws Exception {
        seedEvents(5);

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?actorId=non-existent-user",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                new ParameterizedTypeReference<>() {});

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.totalElements()).isZero();
        assertThat(body.totalPages()).isZero();
        assertThat(body.events()).isEmpty();
    }

    @Test
    @DisplayName("GET query is strictly read-only and never modifies database rows or chain head")
    void testQueryIsReadOnly() throws Exception {
        seedEvents(5);

        Long initialEventCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        Map<String, Object> initialHead = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");

        // Execute multiple queries
        restTemplate.getForEntity("/audit/events?page=0&size=2", String.class);
        restTemplate.getForEntity("/audit/events?actorId=user-1", String.class);
        restTemplate.getForEntity("/audit/events?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", String.class);

        Long finalEventCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        Map<String, Object> finalHead = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");

        assertThat(finalEventCount).isEqualTo(initialEventCount).isEqualTo(5L);
        assertThat(finalHead.get("last_sequence_no")).isEqualTo(initialHead.get("last_sequence_no")).isEqualTo(5L);
        assertThat(finalHead.get("last_record_hash")).isEqualTo(initialHead.get("last_record_hash"));
    }

    @Test
    @DisplayName("Invalid query parameters return sanitized HTTP 400 Bad Request")
    void testInvalidQueryParameters() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/audit/events?size=0", Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("status")).isEqualTo(400);
        assertThat(response.getBody().get("message")).isEqualTo("size must be between 1 and 100");

        ResponseEntity<Map> negPage = restTemplate.getForEntity("/audit/events?page=-1", Map.class);
        assertThat(negPage.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(negPage.getBody().get("message")).isEqualTo("page must not be negative");

        ResponseEntity<Map> badDate = restTemplate.getForEntity("/audit/events?from=invalid-date", Map.class);
        assertThat(badDate.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(badDate.getBody().get("message")).isEqualTo("Invalid timestamp format for 'from'; must be valid ISO-8601 timestamp");

        ResponseEntity<Map> reversed = restTemplate.getForEntity(
                "/audit/events?from=2026-10-15T12:00:01Z&to=2026-10-15T12:00:00Z", Map.class);
        assertThat(reversed.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(reversed.getBody().get("message")).isEqualTo("'from' timestamp must not be after 'to' timestamp");
    }

    @Test
    @DisplayName("Query excludes archived events by default when includeArchived is not specified")
    void testQueryExcludesArchivedEventsByDefault() throws Exception {
        List<AppendEventResult> seeded = seedEvents(3);
        archivalService.archive(seeded.get(1).eventId(), "retention-policy");

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events",
                HttpMethod.GET,
                null,
                EVENT_PAGE_TYPE);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> page = response.getBody();
        assertThat(page).isNotNull();
        assertThat(page.totalElements()).isEqualTo(2);
        assertThat(page.events()).hasSize(2);
        assertThat(page.events().stream().map(AuditEventDto::eventId))
                .containsExactly(seeded.get(0).eventId(), seeded.get(2).eventId());
    }

    @Test
    @DisplayName("Query includes archived events when includeArchived=true and exposes archivedAt")
    void testQueryIncludesArchivedEventsWithFlag() throws Exception {
        List<AppendEventResult> seeded = seedEvents(3);
        archivalService.archive(seeded.get(1).eventId(), "retention-policy");

        ResponseEntity<AuditPageResponse<AuditEventDto>> response = restTemplate.exchange(
                "/audit/events?includeArchived=true",
                HttpMethod.GET,
                null,
                EVENT_PAGE_TYPE);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditPageResponse<AuditEventDto> page = response.getBody();
        assertThat(page).isNotNull();
        assertThat(page.totalElements()).isEqualTo(3);
        assertThat(page.events()).hasSize(3);

        AuditEventDto unarchived1 = page.events().get(0);
        AuditEventDto archived = page.events().get(1);
        AuditEventDto unarchived2 = page.events().get(2);

        assertThat(unarchived1.eventId()).isEqualTo(seeded.get(0).eventId());
        assertThat(unarchived1.archivedAt()).isNull();

        assertThat(archived.eventId()).isEqualTo(seeded.get(1).eventId());
        assertThat(archived.archivedAt()).isNotNull();

        assertThat(unarchived2.eventId()).isEqualTo(seeded.get(2).eventId());
        assertThat(unarchived2.archivedAt()).isNull();
    }

    @Test
    @DisplayName("Query execution with includeArchived maintains read-only database immutability")
    void testQueryReadOnlyInvariantWithArchive() throws Exception {
        List<AppendEventResult> seeded = seedEvents(3);
        archivalService.archive(seeded.get(0).eventId(), "retention-policy");

        Map<String, Object> headBefore = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");
        long countBefore = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        long archiveCountBefore = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event_archive", Long.class);

        restTemplate.exchange("/audit/events?includeArchived=true", HttpMethod.GET, null, EVENT_PAGE_TYPE);
        restTemplate.exchange("/audit/events?includeArchived=false", HttpMethod.GET, null, EVENT_PAGE_TYPE);

        Map<String, Object> headAfter = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");
        long countAfter = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        long archiveCountAfter = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event_archive", Long.class);

        assertThat(headAfter).isEqualTo(headBefore);
        assertThat(countAfter).isEqualTo(countBefore);
        assertThat(archiveCountAfter).isEqualTo(archiveCountBefore);
    }

    private List<AppendEventResult> seedEvents(int count) throws Exception {
        List<AppendEventResult> results = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Thread.sleep(10);
            String eventType = (i % 2 == 0) ? "order.created" : "payment.processed";
            String actorId = "user-" + i;
            String resourceType = (i % 2 == 0) ? "order" : "payment";
            String resourceId = "res-" + i;
            JsonNode payload = objectMapper.readTree("{\"index\":" + i + ",\"data\":\"sample\"}");
            Instant sourceTimestamp = Instant.parse("2026-10-15T00:00:00Z").plusSeconds(i * 60L);

            AppendEventResult result = appendService.append(
                    new AppendEventRequest(eventType, actorId, resourceType, resourceId, payload, sourceTimestamp));
            results.add(result);
        }
        return results;
    }
}
