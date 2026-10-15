package com.example.auditlog.archival;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auditlog.api.AuditEventNotFoundException;
import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.verify.AuditVerificationResponse;
import com.example.auditlog.verify.AuditVerificationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * End-to-end integration tests for {@link AuditArchivalService} against PostgreSQL 16
 * using Testcontainers, Flyway, and Spring Boot application context.
 *
 * <p>Validates single-event archival, idempotency, retention cutoff filtering,
 * immutability of original audit events, and hash-chain verification integrity.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AuditArchivalServiceIntegrationTests {

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
        registry.add("audit.retention.window-days", () -> "30");
    }

    @Autowired
    private AuditAppendService appendService;

    @Autowired
    private AuditArchivalService archivalService;

    @Autowired
    private AuditVerificationService verificationService;

    @Autowired
    private AuditRetentionProperties retentionProperties;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetDatabase() {
        flyway.clean();
        flyway.migrate();
        retentionProperties.setWindowDays(30);
    }

    private AppendEventResult appendSampleEvent(String eventType, String actorId) {
        JsonNode payload = objectMapper.createObjectNode().put("action", "test");
        AppendEventRequest request = new AppendEventRequest(
                eventType, actorId, "DOCUMENT", "doc-1", payload, Instant.now());
        return appendService.append(request);
    }

    private void withTriggersDisabled(String tableName, Runnable action) {
        jdbcTemplate.execute("ALTER TABLE " + tableName + " DISABLE TRIGGER ALL");
        try {
            action.run();
        } finally {
            jdbcTemplate.execute("ALTER TABLE " + tableName + " ENABLE TRIGGER ALL");
        }
    }

    @Test
    @DisplayName("Single-event archival records metadata and preserves original audit_event row")
    void testArchiveSingleEvent_success() {
        AppendEventResult appendResult = appendSampleEvent("DOCUMENT_CREATED", "actor-1");
        UUID eventId = appendResult.eventId();

        Map<String, Object> eventBefore = jdbcTemplate.queryForMap(
                "SELECT * FROM audit_event WHERE event_id = ?::uuid", eventId.toString());

        ArchiveEventResult archiveResult = archivalService.archive(eventId, "policy-retention-90d");

        assertThat(archiveResult.eventId()).isEqualTo(eventId);
        assertThat(archiveResult.policyRef()).isEqualTo("policy-retention-90d");
        assertThat(archiveResult.archivedAt()).isNotNull();

        // Verify audit_event_archive row
        Integer archiveCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event_archive WHERE event_id = ?::uuid", Integer.class, eventId.toString());
        assertThat(archiveCount).isEqualTo(1);

        // Verify audit_event row is 100% identical
        Map<String, Object> eventAfter = jdbcTemplate.queryForMap(
                "SELECT * FROM audit_event WHERE event_id = ?::uuid", eventId.toString());
        assertThat(eventAfter).isEqualTo(eventBefore);
    }

    @Test
    @DisplayName("Single-event archival is idempotent and returns existing record on second call")
    void testArchiveSingleEvent_idempotent() {
        AppendEventResult appendResult = appendSampleEvent("DOCUMENT_CREATED", "actor-1");
        UUID eventId = appendResult.eventId();

        ArchiveEventResult first = archivalService.archive(eventId, "policy-1");
        ArchiveEventResult second = archivalService.archive(eventId, "policy-2");

        assertThat(second.eventId()).isEqualTo(first.eventId());
        assertThat(second.archivedAt()).isEqualTo(first.archivedAt());
        assertThat(second.policyRef()).isEqualTo(first.policyRef());

        Integer count = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event_archive WHERE event_id = ?::uuid", Integer.class, eventId.toString());
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Single-event archival of non-existent event throws AuditEventNotFoundException")
    void testArchiveSingleEvent_notFound() {
        UUID randomId = UUID.randomUUID();
        assertThatThrownBy(() -> archivalService.archive(randomId, "policy-1"))
                .isInstanceOf(AuditEventNotFoundException.class)
                .hasMessageContaining(randomId.toString());
    }

    @Test
    @DisplayName("Single-event archival with blank policyRef throws IllegalArgumentException")
    void testArchiveSingleEvent_blankPolicyRef() {
        AppendEventResult appendResult = appendSampleEvent("DOCUMENT_CREATED", "actor-1");
        UUID eventId = appendResult.eventId();

        assertThatThrownBy(() -> archivalService.archive(eventId, "   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("policyRef must not be blank");
    }

    @Test
    @DisplayName("Batch archival archives only events older than configured retention cutoff")
    void testArchiveEligible_archivesOnlyEventsBeyondCutoff() {
        AppendEventResult event1 = appendSampleEvent("EVENT_1", "actor-1");
        AppendEventResult event2 = appendSampleEvent("EVENT_2", "actor-2");
        AppendEventResult event3 = appendSampleEvent("EVENT_3", "actor-3");

        // Set event1 and event2 to 45 and 60 days in the past (retention window is 30 days)
        Instant pastDate45 = Instant.now().minus(45, ChronoUnit.DAYS);
        Instant pastDate60 = Instant.now().minus(60, ChronoUnit.DAYS);

        // Update recorded_at via superuser test connection with triggers disabled
        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("UPDATE audit_event SET recorded_at = ? WHERE event_id = ?::uuid",
                    java.sql.Timestamp.from(pastDate60), event1.eventId().toString());
            jdbcTemplate.update("UPDATE audit_event SET recorded_at = ? WHERE event_id = ?::uuid",
                    java.sql.Timestamp.from(pastDate45), event2.eventId().toString());
        });
        // event3 remains recent (now)

        int archivedCount = archivalService.archiveEligible("retention-30d");
        assertThat(archivedCount).isEqualTo(2);

        // Verify event1 and event2 are archived, event3 is not
        Boolean event1Archived = jdbcTemplate.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM audit_event_archive WHERE event_id = ?::uuid)", Boolean.class, event1.eventId().toString());
        Boolean event2Archived = jdbcTemplate.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM audit_event_archive WHERE event_id = ?::uuid)", Boolean.class, event2.eventId().toString());
        Boolean event3Archived = jdbcTemplate.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM audit_event_archive WHERE event_id = ?::uuid)", Boolean.class, event3.eventId().toString());

        assertThat(event1Archived).isTrue();
        assertThat(event2Archived).isTrue();
        assertThat(event3Archived).isFalse();
    }

    @Test
    @DisplayName("Batch archival is idempotent: second run archives 0 additional events")
    void testArchiveEligible_idempotent() {
        AppendEventResult event1 = appendSampleEvent("EVENT_1", "actor-1");
        Instant pastDate = Instant.now().minus(45, ChronoUnit.DAYS);
        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("UPDATE audit_event SET recorded_at = ? WHERE event_id = ?::uuid",
                    java.sql.Timestamp.from(pastDate), event1.eventId().toString());
        });

        int firstRun = archivalService.archiveEligible("retention-30d");
        assertThat(firstRun).isEqualTo(1);

        int secondRun = archivalService.archiveEligible("retention-30d");
        assertThat(secondRun).isZero();
    }

    @Test
    @DisplayName("Batch archival leaves all audit_event hash columns and records completely intact")
    void testArchiveEligible_leavesAuditEventRowsUnmodified() {
        AppendEventResult event1 = appendSampleEvent("EVENT_1", "actor-1");
        Instant pastDate = Instant.now().minus(45, ChronoUnit.DAYS);
        withTriggersDisabled("audit_event", () -> {
            jdbcTemplate.update("UPDATE audit_event SET recorded_at = ? WHERE event_id = ?::uuid",
                    java.sql.Timestamp.from(pastDate), event1.eventId().toString());
        });

        Map<String, Object> before = jdbcTemplate.queryForMap(
                "SELECT content_hash, record_hash, previous_hash, payload FROM audit_event WHERE event_id = ?::uuid",
                event1.eventId().toString());

        archivalService.archiveEligible("retention-30d");

        Map<String, Object> after = jdbcTemplate.queryForMap(
                "SELECT content_hash, record_hash, previous_hash, payload FROM audit_event WHERE event_id = ?::uuid",
                event1.eventId().toString());

        assertThat(after).isEqualTo(before);
    }

    @Test
    @DisplayName("Full chain verification remains INTACT and scans all events after archival")
    void testVerifyChainIntactAfterArchival() {
        AppendEventResult event1 = appendSampleEvent("EVENT_1", "actor-1");
        AppendEventResult event2 = appendSampleEvent("EVENT_2", "actor-2");
        AppendEventResult event3 = appendSampleEvent("EVENT_3", "actor-3");

        // Archive event1 and event2 individually
        archivalService.archive(event1.eventId(), "policy-1");
        archivalService.archive(event2.eventId(), "policy-1");

        // Verify chain: all 3 events must be scanned and verified
        AuditVerificationResponse response = verificationService.verifyChain();

        assertThat(response.status()).isEqualTo("INTACT");
        assertThat(response.recordsVerified()).isEqualTo(3L);
        assertThat(response.headSequenceNo()).isEqualTo(3L);
        assertThat(response.lastVerifiedSequenceNo()).isEqualTo(3L);
        assertThat(response.violation()).isNull();
    }

    @Test
    @DisplayName("Batch archival fails when retention window is null or non-positive")
    void testArchiveEligible_failsWhenWindowNotPositive() {
        retentionProperties.setWindowDays(0);
        assertThatThrownBy(() -> archivalService.archiveEligible("policy-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("positive integer");

        retentionProperties.setWindowDays(-5);
        assertThatThrownBy(() -> archivalService.archiveEligible("policy-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("positive integer");

        retentionProperties.setWindowDays(null);
        assertThatThrownBy(() -> archivalService.archiveEligible("policy-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("positive integer");
    }
}
