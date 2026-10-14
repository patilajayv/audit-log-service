package com.example.auditlog.verify;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.hashing.AuditHashService;
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
 * End-to-end integration tests for {@code GET /audit/verify} against PostgreSQL 16
 * using Testcontainers, Flyway, embedded web server, and {@link TestRestTemplate}.
 *
 * <p>Validates intact chain verification, empty chain baseline, read-only behavior,
 * and comprehensive tamper detection across payload modifications, stored hash alterations,
 * broken hash pointers, sequence gaps, and chain-head tampering.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditVerificationIntegrationTests {

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
    @DisplayName("Empty database reports INTACT status with genesis hash and 0 verified records")
    void testVerifyEmptyChain() {
        ResponseEntity<AuditVerificationResponse> response = restTemplate.exchange(
                "/audit/verify",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_INTACT);
        assertThat(body.recordsVerified()).isZero();
        assertThat(body.headSequenceNo()).isZero();
        assertThat(body.headRecordHash()).isEqualTo(AuditHashService.GENESIS_HASH);
        assertThat(body.lastVerifiedSequenceNo()).isZero();
        assertThat(body.lastVerifiedRecordHash()).isEqualTo(AuditHashService.GENESIS_HASH);
        assertThat(body.violation()).isNull();
    }

    @Test
    @DisplayName("Single event chain reports INTACT status")
    void testVerifySingleEventChain() throws Exception {
        seedEvents(1);

        ResponseEntity<AuditVerificationResponse> response = restTemplate.exchange(
                "/audit/verify",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_INTACT);
        assertThat(body.recordsVerified()).isEqualTo(1L);
        assertThat(body.headSequenceNo()).isEqualTo(1L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(1L);
        assertThat(body.headRecordHash()).isEqualTo(body.lastVerifiedRecordHash());
        assertThat(body.violation()).isNull();
    }

    @Test
    @DisplayName("Multiple event chain (10 events) reports INTACT status with matching head hash")
    void testVerifyMultiEventChain() throws Exception {
        seedEvents(10);

        ResponseEntity<AuditVerificationResponse> response = restTemplate.exchange(
                "/audit/verify",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_INTACT);
        assertThat(body.recordsVerified()).isEqualTo(10L);
        assertThat(body.headSequenceNo()).isEqualTo(10L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(10L);
        assertThat(body.headRecordHash()).isEqualTo(body.lastVerifiedRecordHash());
        assertThat(body.violation()).isNull();
    }

    @Test
    @DisplayName("Tamper test: altering event payload triggers CONTENT_HASH_MISMATCH")
    void testTamperPayload_detectsContentHashMismatch() throws Exception {
        seedEvents(5);

        // Administratively alter payload of sequence 3
        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_event SET payload = '{\"tampered\": true}'::jsonb WHERE sequence_no = 3");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(2L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(2L);
        assertThat(body.headSequenceNo()).isEqualTo(5L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(3L);
        assertThat(body.violation().message()).contains("Content hash mismatch at sequence 3");
    }

    @Test
    @DisplayName("Tamper test: altering stored content_hash triggers CONTENT_HASH_MISMATCH")
    void testTamperStoredContentHash_detectsContentHashMismatch() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_event SET content_hash = repeat('a', 64) WHERE sequence_no = 2");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(1L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(2L);
    }

    @Test
    @DisplayName("Tamper test: altering previous_hash at sequence 1 triggers GENESIS_MISMATCH")
    void testTamperGenesisHash_detectsGenesisMismatch() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_event SET previous_hash = repeat('1', 64) WHERE sequence_no = 1");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isZero();
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.GENESIS_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(1L);
        assertThat(body.violation().expected()).isEqualTo(AuditHashService.GENESIS_HASH);
        assertThat(body.violation().actual()).isEqualTo("1".repeat(64));
    }

    @Test
    @DisplayName("Tamper test: altering previous_hash at sequence 3 triggers PREVIOUS_HASH_MISMATCH")
    void testTamperMiddlePreviousHash_detectsPreviousHashMismatch() throws Exception {
        seedEvents(4);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_event SET previous_hash = repeat('f', 64) WHERE sequence_no = 3");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(2L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(2L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.PREVIOUS_HASH_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(3L);
    }

    @Test
    @DisplayName("Tamper test: altering stored record_hash triggers RECORD_HASH_MISMATCH")
    void testTamperRecordHash_detectsRecordHashMismatch() throws Exception {
        seedEvents(4);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_event SET record_hash = repeat('e', 64) WHERE sequence_no = 2");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(1L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.RECORD_HASH_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(2L);
    }

    @Test
    @DisplayName("Tamper test: deleting middle event triggers SEQUENCE_GAP")
    void testTamperDeleteMiddleRecord_detectsSequenceGap() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("DELETE FROM audit_event WHERE sequence_no = 2");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(1L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(1L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.SEQUENCE_GAP);
        assertThat(body.violation().sequenceNo()).isEqualTo(2L);
        assertThat(body.violation().expected()).isEqualTo("2");
        assertThat(body.violation().actual()).isEqualTo("3");
    }

    @Test
    @DisplayName("Tamper test: deleting first event triggers SEQUENCE_GAP")
    void testTamperDeleteFirstRecord_detectsSequenceGap() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("DELETE FROM audit_event WHERE sequence_no = 1");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isZero();
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.SEQUENCE_GAP);
        assertThat(body.violation().sequenceNo()).isEqualTo(1L);
        assertThat(body.violation().expected()).isEqualTo("1");
        assertThat(body.violation().actual()).isEqualTo("2");
    }

    @Test
    @DisplayName("Tamper test: deleting trailing event triggers CHAIN_HEAD_MISMATCH")
    void testTamperDeleteTrailingRecord_detectsChainHeadMismatch() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("DELETE FROM audit_event WHERE sequence_no = 3");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(2L);
        assertThat(body.lastVerifiedSequenceNo()).isEqualTo(2L);
        assertThat(body.headSequenceNo()).isEqualTo(3L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CHAIN_HEAD_MISMATCH);
        assertThat(body.violation().sequenceNo()).isEqualTo(3L);
        assertThat(body.violation().expected()).isEqualTo("3");
        assertThat(body.violation().actual()).isEqualTo("2");
    }

    @Test
    @DisplayName("Tamper test: altering chain head record hash triggers CHAIN_HEAD_MISMATCH")
    void testTamperAlterChainHeadRecordHash_detectsChainHeadMismatch() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_chain_head", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_chain_head SET last_record_hash = repeat('9', 64) WHERE chain_id = 1");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(3L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CHAIN_HEAD_MISMATCH);
        assertThat(body.violation().expected()).isEqualTo("9".repeat(64));
    }

    @Test
    @DisplayName("Tamper test: altering chain head sequence number triggers CHAIN_HEAD_MISMATCH")
    void testTamperAlterChainHeadSequenceNo_detectsChainHeadMismatch() throws Exception {
        seedEvents(3);

        withTriggersDisabled("audit_chain_head", () -> {
            jdbcTemplate.update(
                    "UPDATE audit_chain_head SET last_sequence_no = 99 WHERE chain_id = 1");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.recordsVerified()).isEqualTo(3L);
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CHAIN_HEAD_MISMATCH);
        assertThat(body.violation().expected()).isEqualTo("99");
        assertThat(body.violation().actual()).isEqualTo("3");
    }

    @Test
    @DisplayName("Missing audit_chain_head singleton row is reported as CHAIN_HEAD_MISMATCH")
    void testMissingChainHeadRow_detectsChainHeadMismatch() {
        withTriggersDisabled("audit_chain_head", () -> {
            jdbcTemplate.update("DELETE FROM audit_chain_head WHERE chain_id = 1");
        });

        ResponseEntity<AuditVerificationResponse> response = restTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        AuditVerificationResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.status()).isEqualTo(AuditVerificationResponse.STATUS_CORRUPTED);
        assertThat(body.headSequenceNo()).isNull();
        assertThat(body.headRecordHash()).isNull();
        assertThat(body.violation()).isNotNull();
        assertThat(body.violation().type()).isEqualTo(ChainViolationType.CHAIN_HEAD_MISMATCH);
        assertThat(body.violation().message()).contains("audit_chain_head singleton record is missing");
    }

    @Test
    @DisplayName("GET /audit/verify is strictly read-only and never mutates rows or chain head")
    void testVerifyIsReadOnly() throws Exception {
        seedEvents(3);

        Long initialCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        Map<String, Object> initialHead = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");

        // Execute verify multiple times
        restTemplate.getForEntity("/audit/verify", AuditVerificationResponse.class);
        restTemplate.getForEntity("/audit/verify", AuditVerificationResponse.class);

        Long finalCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);
        Map<String, Object> finalHead = jdbcTemplate.queryForMap(
                "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1");

        assertThat(finalCount).isEqualTo(initialCount).isEqualTo(3L);
        assertThat(finalHead.get("last_sequence_no")).isEqualTo(initialHead.get("last_sequence_no")).isEqualTo(3L);
        assertThat(finalHead.get("last_record_hash")).isEqualTo(initialHead.get("last_record_hash"));
    }

    private void withTriggersDisabled(String tableName, Runnable action) {
        jdbcTemplate.execute("ALTER TABLE " + tableName + " DISABLE TRIGGER ALL");
        try {
            action.run();
        } finally {
            jdbcTemplate.execute("ALTER TABLE " + tableName + " ENABLE TRIGGER ALL");
        }
    }

    private List<AppendEventResult> seedEvents(int count) throws Exception {
        List<AppendEventResult> results = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Thread.sleep(10);
            String eventType = (i % 2 == 0) ? "account.deposit" : "account.withdrawal";
            String actorId = "user-" + i;
            String resourceType = "account";
            String resourceId = "acc-" + i;
            JsonNode payload = objectMapper.readTree("{\"index\":" + i + ",\"amount\":100}");
            Instant sourceTimestamp = Instant.parse("2026-10-15T00:00:00Z").plusSeconds(i * 60L);

            AppendEventResult result = appendService.append(
                    new AppendEventRequest(eventType, actorId, resourceType, resourceId, payload, sourceTimestamp));
            results.add(result);
        }
        return results;
    }
}
