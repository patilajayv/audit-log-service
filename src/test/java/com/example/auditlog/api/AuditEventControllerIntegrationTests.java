package com.example.auditlog.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
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
 * End-to-end integration tests for {@code POST /audit/events} using an isolated
 * Testcontainers PostgreSQL database, embedded Tomcat HTTP server, and {@link TestRestTemplate}.
 *
 * <p>Verifies HTTP protocol semantics, request size limits, duplicate key detection,
 * transactional integrity, and cryptographic hash chain linkage under sequential and concurrent loads.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditEventControllerIntegrationTests {

    private static final String GENESIS_HASH = "0".repeat(64);
    private static final Duration CONCURRENCY_TIMEOUT = Duration.ofSeconds(15);

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) throws SQLException {
        POSTGRES.start();
        // Create the audit_app role granted by V1 migration
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
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void cleanAndMigrate() {
        this.restTemplate = rawRestTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        flyway.clean();
        flyway.migrate();
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Test
    void httpAppendFromGenesisCreatesEventAndAdvancesHead() {
        String requestJson = """
                {
                    "eventType": "USER_LOGIN",
                    "actorId": "user-42",
                    "resourceType": "SESSION",
                    "resourceId": "sess-99",
                    "payload": {
                        "ip": "192.168.1.1",
                        "status": "SUCCESS"
                    }
                }
                """;

        HttpEntity<String> request = new HttpEntity<>(requestJson, jsonHeaders());
        ResponseEntity<AuditEventResponse> response = restTemplate.postForEntity(
                "/audit/events", request, AuditEventResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        AuditEventResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.sequenceNo()).isEqualTo(1L);
        assertThat(body.previousHash()).isEqualTo(GENESIS_HASH);
        assertThat(body.eventId()).isNotNull();
        assertThat(body.contentHash()).matches("^[0-9a-f]{64}$");
        assertThat(body.recordHash()).matches("^[0-9a-f]{64}$");
        assertThat(body.recordedAt()).isNotNull();

        // Verify database persistence
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(1L);

        Map<String, Object> eventRow = jdbcTemplate.queryForMap(
                "SELECT sequence_no, event_type, actor_id, resource_type, resource_id, "
                        + "canonicalization_version, previous_hash, record_hash FROM audit_event WHERE sequence_no = 1");
        assertThat(eventRow.get("sequence_no")).isEqualTo(1L);
        assertThat(eventRow.get("event_type")).isEqualTo("USER_LOGIN");
        assertThat(eventRow.get("actor_id")).isEqualTo("user-42");
        assertThat(eventRow.get("resource_type")).isEqualTo("SESSION");
        assertThat(eventRow.get("resource_id")).isEqualTo("sess-99");
        assertThat(eventRow.get("canonicalization_version")).isEqualTo("JCS-1");
        assertThat(eventRow.get("previous_hash")).isEqualTo(GENESIS_HASH);
        assertThat(eventRow.get("record_hash")).isEqualTo(body.recordHash());

        // Verify chain head
        Long headSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String headHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);
        assertThat(headSeq).isEqualTo(1L);
        assertThat(headHash).isEqualTo(body.recordHash());
    }

    @Test
    void httpAppendChainsConsecutiveEventsWithNormalizedTimestamp() {
        // Event 1 with explicit UTC timestamp
        String req1 = """
                {
                    "eventType": "ORDER_CREATED",
                    "actorId": "trader-1",
                    "resourceType": "ORDER",
                    "resourceId": "ord-100",
                    "payload": {"ticker": "SCHW", "qty": 50},
                    "sourceTimestamp": "2026-10-14T10:00:00.000Z"
                }
                """;
        ResponseEntity<AuditEventResponse> resp1 = restTemplate.postForEntity(
                "/audit/events", new HttpEntity<>(req1, jsonHeaders()), AuditEventResponse.class);
        assertThat(resp1.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        AuditEventResponse body1 = resp1.getBody();
        assertThat(body1).isNotNull();
        assertThat(body1.sequenceNo()).isEqualTo(1L);
        assertThat(body1.previousHash()).isEqualTo(GENESIS_HASH);

        // Event 2 with offset-bearing timestamp (+02:00)
        String req2 = """
                {
                    "eventType": "ORDER_FILLED",
                    "actorId": "system-exec",
                    "resourceType": "ORDER",
                    "resourceId": "ord-100",
                    "payload": {"price": "72.50", "status": "FILLED"},
                    "sourceTimestamp": "2026-10-14T12:00:00+02:00"
                }
                """;
        ResponseEntity<AuditEventResponse> resp2 = restTemplate.postForEntity(
                "/audit/events", new HttpEntity<>(req2, jsonHeaders()), AuditEventResponse.class);
        assertThat(resp2.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        AuditEventResponse body2 = resp2.getBody();
        assertThat(body2).isNotNull();
        assertThat(body2.sequenceNo()).isEqualTo(2L);
        assertThat(body2.previousHash()).isEqualTo(body1.recordHash());

        // Verify database chain state
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(2L);

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT sequence_no, previous_hash, record_hash, source_timestamp FROM audit_event ORDER BY sequence_no ASC");
        assertThat(rows.get(0).get("previous_hash")).isEqualTo(GENESIS_HASH);
        assertThat(rows.get(1).get("previous_hash")).isEqualTo(rows.get(0).get("record_hash"));
        assertThat(rows.get(1).get("record_hash")).isEqualTo(body2.recordHash());

        // Verify chain head
        Long headSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String headHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);
        assertThat(headSeq).isEqualTo(2L);
        assertThat(headHash).isEqualTo(body2.recordHash());
    }

    @Test
    void httpConcurrentAppendsChainIntegrity() throws Exception {
        int threadCount = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        try {
            List<Callable<ResponseEntity<AuditEventResponse>>> tasks = new ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                final int idx = i;
                tasks.add(() -> {
                    String json = String.format("""
                            {
                                "eventType": "CONCURRENT_TEST_%d",
                                "actorId": "thread-%d",
                                "resourceType": "RECORD",
                                "resourceId": "rec-%d",
                                "payload": {"index": %d}
                            }
                            """, idx, idx, idx, idx);
                    return restTemplate.postForEntity(
                            "/audit/events", new HttpEntity<>(json, jsonHeaders()), AuditEventResponse.class);
                });
            }

            List<Future<ResponseEntity<AuditEventResponse>>> futures = executor.invokeAll(tasks);
            List<AuditEventResponse> responses = new ArrayList<>();

            for (Future<ResponseEntity<AuditEventResponse>> future : futures) {
                ResponseEntity<AuditEventResponse> resp = future.get(CONCURRENCY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
                assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                responses.add(resp.getBody());
            }

            // Assert all 8 returned distinct sequence numbers 1..8
            List<Long> returnSeqs = responses.stream().map(AuditEventResponse::sequenceNo).sorted().toList();
            assertThat(returnSeqs).containsExactly(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L);

            // Assert database contains exactly 8 events
            Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
            assertThat(count).isEqualTo((long) threadCount);

            // Fetch and verify cryptographic hash chain integrity in DB
            List<Map<String, Object>> dbEvents = jdbcTemplate.queryForList(
                    "SELECT sequence_no, previous_hash, record_hash FROM audit_event ORDER BY sequence_no ASC");
            assertThat(dbEvents).hasSize(threadCount);

            assertThat(dbEvents.get(0).get("previous_hash")).isEqualTo(GENESIS_HASH);
            for (int i = 1; i < threadCount; i++) {
                String prevRecordHash = (String) dbEvents.get(i - 1).get("record_hash");
                String currentPreviousHash = (String) dbEvents.get(i).get("previous_hash");
                assertThat(currentPreviousHash)
                        .as("Event %d previous_hash must equal event %d record_hash", i + 1, i)
                        .isEqualTo(prevRecordHash);
            }

            // Chain head must match the last event exactly
            Long headSeq = jdbcTemplate.queryForObject(
                    "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
            String headHash = jdbcTemplate.queryForObject(
                    "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);
            assertThat(headSeq).isEqualTo(8L);
            assertThat(headHash).isEqualTo(dbEvents.get(7).get("record_hash"));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void httpOversizedRequestDoesNotInsertEventOrAdvanceHead() throws Exception {
        // Construct payload > 1 MiB (1,100,000 bytes padding)
        String bigPadding = "x".repeat(1_100_000);
        String oversizedJson = String.format("""
                {
                    "eventType": "OVERSIZED_TEST",
                    "actorId": "user-large",
                    "resourceType": "DOCUMENT",
                    "resourceId": "doc-large",
                    "payload": {
                        "content": "%s"
                    }
                }
                """, bigPadding);

        HttpEntity<String> request = new HttpEntity<>(oversizedJson, jsonHeaders());
        ResponseEntity<String> response = restTemplate.postForEntity("/audit/events", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        JsonNode errorNode = objectMapper.readTree(response.getBody());
        assertThat(errorNode.get("status").asInt()).isEqualTo(413);
        assertThat(errorNode.get("error").asText()).isEqualTo("Payload Too Large");
        assertThat(errorNode.get("message").asText()).contains("1048576");
        assertThat(errorNode.get("timestamp").asText()).isNotEmpty();

        // Database must remain completely untouched
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(0L);

        Long headSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String headHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);
        assertThat(headSeq).isEqualTo(0L);
        assertThat(headHash).isEqualTo(GENESIS_HASH);
    }

    @Test
    void httpValidationFailureDoesNotInsertEventOrAdvanceHead() throws Exception {
        // Missing eventType and actorId
        String invalidJson = """
                {
                    "resourceType": "ACCOUNT",
                    "resourceId": "acc-1",
                    "payload": {}
                }
                """;

        HttpEntity<String> request = new HttpEntity<>(invalidJson, jsonHeaders());
        ResponseEntity<String> response = restTemplate.postForEntity("/audit/events", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode errorNode = objectMapper.readTree(response.getBody());
        assertThat(errorNode.get("status").asInt()).isEqualTo(400);
        assertThat(errorNode.get("error").asText()).isEqualTo("Bad Request");
        assertThat(errorNode.get("message").asText()).contains("eventType must not be null or blank");

        // Database must remain completely untouched
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(0L);

        Long headSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String headHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);
        assertThat(headSeq).isEqualTo(0L);
        assertThat(headHash).isEqualTo(GENESIS_HASH);
    }

    @Test
    void httpDuplicateKeyAtRootRejectedWithSanitizedBadRequest() throws Exception {
        String duplicateRootKeyJson = """
                {
                    "eventType": "LOGIN",
                    "actorId": "user-1",
                    "eventType": "LOGOUT",
                    "resourceType": "ACCOUNT",
                    "resourceId": "acc-1",
                    "payload": {}
                }
                """;

        HttpEntity<String> request = new HttpEntity<>(duplicateRootKeyJson, jsonHeaders());
        ResponseEntity<String> response = restTemplate.postForEntity("/audit/events", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode errorNode = objectMapper.readTree(response.getBody());
        assertThat(errorNode.get("status").asInt()).isEqualTo(400);
        assertThat(errorNode.get("error").asText()).isEqualTo("Bad Request");
        assertThat(errorNode.get("message").asText()).contains("Duplicate JSON property: 'eventType'");

        // Database remains empty
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(0L);
    }

    @Test
    void httpDuplicateKeyInNestedPayloadRejectedWithSanitizedBadRequest() throws Exception {
        String duplicateNestedKeyJson = """
                {
                    "eventType": "UPDATE",
                    "actorId": "user-1",
                    "resourceType": "SETTINGS",
                    "resourceId": "s-1",
                    "payload": {
                        "theme": "dark",
                        "theme": "light"
                    }
                }
                """;

        HttpEntity<String> request = new HttpEntity<>(duplicateNestedKeyJson, jsonHeaders());
        ResponseEntity<String> response = restTemplate.postForEntity("/audit/events", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode errorNode = objectMapper.readTree(response.getBody());
        assertThat(errorNode.get("status").asInt()).isEqualTo(400);
        assertThat(errorNode.get("error").asText()).isEqualTo("Bad Request");
        assertThat(errorNode.get("message").asText()).contains("Duplicate JSON property: 'theme'");

        // Database remains empty
        Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        assertThat(count).isEqualTo(0L);
    }
}
