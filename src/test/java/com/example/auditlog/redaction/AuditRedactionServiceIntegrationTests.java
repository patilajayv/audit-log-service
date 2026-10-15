package com.example.auditlog.redaction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auditlog.api.AuditEventNotFoundException;
import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.crypto.AuditCryptoService;
import com.example.auditlog.crypto.EncryptedEnvelope;
import com.example.auditlog.crypto.InMemoryKeyManager;
import com.example.auditlog.crypto.KeyDestroyedException;
import com.example.auditlog.crypto.KeyManager;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.query.AuditQueryCriteria;
import com.example.auditlog.query.AuditQueryService;
import com.example.auditlog.verify.AuditVerificationResponse;
import com.example.auditlog.verify.AuditVerificationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
 * End-to-end integration tests for {@link AuditRedactionService} against PostgreSQL 16
 * using Testcontainers, Flyway V4, and the full Spring application context.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AuditRedactionServiceIntegrationTests {

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
    private AuditAppendService appendService;

    @Autowired
    private AuditRedactionService redactionService;

    @Autowired
    private AuditVerificationService verificationService;

    @Autowired
    private AuditQueryService queryService;

    @Autowired
    private AuditCryptoService cryptoService;

    @Autowired
    private InMemoryKeyManager keyManager;

    @Autowired
    private AuditRedactionCoordinator coordinator;

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
    }

    @Test
    @DisplayName("Plaintext legacy event redaction masks read projection without mutating audit_event")
    void testLegacyPlaintextEventRedaction() {
        // 1. Ingest legacy plaintext event
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("accountNumber", "12345678");
        payload.put("action", "TRANSFER");
        payload.put("amount", 1000);

        AppendEventRequest request = new AppendEventRequest(
                "FUND_TRANSFER", "actor-1", "ACCOUNT", "acct-100", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();
        long originalSeq = appendResult.sequenceNo();
        String originalContentHash = appendResult.contentHash();
        String originalRecordHash = appendResult.recordHash();

        // 2. Perform redaction
        RedactionRequest redactReq = new RedactionRequest("accountNumber", "GDPR_ARTICLE_17", "privacy-officer-1");
        RedactionResult result = redactionService.redact(eventId, redactReq);

        assertThat(result.eventId()).isEqualTo(eventId);
        assertThat(result.fieldPath()).isEqualTo("accountNumber");
        assertThat(result.redactionType()).isEqualTo("MASKED");
        assertThat(result.status()).isEqualTo("COMPLETED");
        assertThat(result.metaAuditSequenceNo()).isEqualTo(originalSeq + 1);

        // 3. Confirm audit_event row for original event is completely untouched
        Map<String, Object> storedEvent = jdbcTemplate.queryForMap(
                "SELECT content_hash, record_hash, payload FROM audit_event WHERE event_id = ?::uuid",
                eventId.toString());
        assertThat(storedEvent.get("content_hash")).isEqualTo(originalContentHash);
        assertThat(storedEvent.get("record_hash")).isEqualTo(originalRecordHash);
        assertThat(storedEvent.get("payload").toString()).contains("12345678"); // Ledger row preserves raw hash commitments

        // 4. Confirm meta-audit event is appended to the ledger
        Map<String, Object> metaRow = jdbcTemplate.queryForMap(
                "SELECT event_type, payload FROM audit_event WHERE sequence_no = ?",
                result.metaAuditSequenceNo());
        assertThat(metaRow.get("event_type")).isEqualTo("PAYLOAD_REDACTED");
        String metaPayloadJson = metaRow.get("payload").toString();
        assertThat(metaPayloadJson).doesNotContain("12345678"); // Zero plaintext disclosure
        assertThat(metaPayloadJson).contains("accountNumber");
        assertThat(metaPayloadJson).contains("GDPR_ARTICLE_17");

        // 5. Audit chain verification is 100% INTACT
        AuditVerificationResponse verifyRes = verificationService.verifyChain();
        assertThat(verifyRes.status()).isEqualTo("INTACT");
        assertThat(verifyRes.recordsVerified()).isEqualTo(2);

        // 6. Query API returns [REDACTED] in projected payload
        AuditQueryCriteria criteria = AuditQueryCriteria.of(null, null, null, null, null, null, 0, 20, false);
        AuditPageResponse<AuditEventDto> page = queryService.query(criteria);
        AuditEventDto projected = page.events().stream()
                .filter(e -> e.eventId().equals(eventId))
                .findFirst()
                .orElseThrow();
        assertThat(projected.payload().path("accountNumber").asText()).isEqualTo("[REDACTED]");
        assertThat(projected.payload().path("action").asText()).isEqualTo("TRANSFER");
        assertThat(projected.contentHash()).isEqualTo(originalContentHash);
        assertThat(projected.recordHash()).isEqualTo(originalRecordHash);
    }

    @Test
    @DisplayName("Encrypted envelope redaction destroys key and performs cryptographic erasure")
    void testEncryptedEnvelopeCryptoShredding() {
        String keyId = "dek-evt-envelope-1";
        String secretValue = "secret-tax-id-999-88-7777";
        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, secretValue);
        assertThat(keyManager.isKeyActive(keyId)).isTrue();

        // 1. Ingest event containing EncryptedEnvelope object
        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("taxIdentifier", objectMapper.valueToTree(envelope));
        payload.put("taxYear", 2026);

        AppendEventRequest request = new AppendEventRequest(
                "TAX_FILING", "actor-tax", "TAXPAYER", "tp-1", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();

        // 2. Perform redaction on the envelope field
        RedactionRequest redactReq = new RedactionRequest("taxIdentifier", "CCPA_ERASURE", "officer-tax");
        RedactionResult result = redactionService.redact(eventId, redactReq);

        assertThat(result.redactionType()).isEqualTo("CRYPTO_SHREDDED");
        assertThat(result.status()).isEqualTo("COMPLETED");

        // 3. Confirm DEK is destroyed in key manager
        assertThat(keyManager.isKeyActive(keyId)).isFalse();
        assertThatThrownBy(() -> cryptoService.decrypt(envelope))
                .isInstanceOf(KeyDestroyedException.class)
                .hasMessageContaining(keyId);

        // 4. Stored ciphertext remains in audit_event (ledger untouched)
        Map<String, Object> storedEvent = jdbcTemplate.queryForMap(
                "SELECT payload FROM audit_event WHERE event_id = ?::uuid",
                eventId.toString());
        assertThat(storedEvent.get("payload").toString()).contains("EncryptedEnvelope");
        assertThat(storedEvent.get("payload").toString()).doesNotContain(secretValue);

        // 5. Audit chain verification is 100% INTACT
        AuditVerificationResponse verifyEnvelopeRes = verificationService.verifyChain();
        assertThat(verifyEnvelopeRes.status()).isEqualTo("INTACT");

        // 6. Query projection returns [REDACTED]
        AuditQueryCriteria queryCriteria = AuditQueryCriteria.of(null, null, null, null, null, null, 0, 20, false);
        AuditPageResponse<AuditEventDto> envelopePage = queryService.query(queryCriteria);
        AuditEventDto projectedEnvelope = envelopePage.events().stream()
                .filter(e -> e.eventId().equals(eventId))
                .findFirst()
                .orElseThrow();
        assertThat(projectedEnvelope.payload().path("taxIdentifier").asText()).isEqualTo("[REDACTED]");
    }

    @Test
    @DisplayName("Redaction request is idempotent and does not append duplicate meta-events")
    void testRedactionIdempotency() {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("ssn", "000-00-0000");

        AppendEventRequest request = new AppendEventRequest(
                "USER_ENROLL", "actor-1", "USER", "u-1", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();

        RedactionRequest redactReq = new RedactionRequest("ssn", "PRIVACY_REQUEST", "admin");

        RedactionResult firstResult = redactionService.redact(eventId, redactReq);
        Long totalEventsAfterFirst = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);

        RedactionResult secondResult = redactionService.redact(eventId, redactReq);
        Long totalEventsAfterSecond = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);

        assertThat(secondResult.metaAuditSequenceNo()).isEqualTo(firstResult.metaAuditSequenceNo());
        assertThat(secondResult.status()).isEqualTo("COMPLETED");
        assertThat(totalEventsAfterSecond).isEqualTo(totalEventsAfterFirst);
    }

    @Test
    @DisplayName("Reconciliation discovery discovers pre-existing meta-event without re-appending")
    void testReconciliationDiscoveryOnRetry() {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("pin", "1234");

        AppendEventRequest request = new AppendEventRequest(
                "AUTH_SET_PIN", "actor-1", "USER", "u-pin", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();

        String operationId = "redact:" + eventId + ":pin";

        // Simulate an earlier partial attempt that appended PAYLOAD_REDACTED to audit_event
        ObjectNode metaPayload = objectMapper.createObjectNode();
        metaPayload.put("redactionOperationId", operationId);
        metaPayload.put("targetEventId", eventId.toString());
        metaPayload.put("targetSequenceNo", appendResult.sequenceNo());
        metaPayload.put("fieldPath", "pin");
        metaPayload.put("reason", "SECURITY_RESET");
        metaPayload.put("redactionType", "MASKED");

        AppendEventResult partialMetaAppend = appendService.append(new AppendEventRequest(
                "PAYLOAD_REDACTED", "officer", "USER", "u-pin", metaPayload, Instant.now()));
        long preExistingMetaSeq = partialMetaAppend.sequenceNo();

        // Simulate audit_event_redaction row left in KEY_DESTROYED status
        jdbcTemplate.update("""
                INSERT INTO audit_event_redaction (
                    operation_id, event_id, field_path, reason, requested_by, redaction_type, status
                ) VALUES (?, ?::uuid, 'pin', 'SECURITY_RESET', 'officer', 'MASKED', 'KEY_DESTROYED')
                """, operationId, eventId.toString());

        long eventsBefore = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);

        // When redaction is retried
        RedactionResult result = redactionService.redact(
                eventId, new RedactionRequest("pin", "SECURITY_RESET", "officer"));

        long eventsAfter = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Long.class);

        // It reconciles and links the pre-existing sequence number without duplicate append
        assertThat(result.metaAuditSequenceNo()).isEqualTo(preExistingMetaSeq);
        assertThat(result.status()).isEqualTo("COMPLETED");
        assertThat(eventsAfter).isEqualTo(eventsBefore);
    }

    @Test
    @DisplayName("Concurrent redactions serialize cleanly and produce exactly one meta-event")
    void testConcurrentRedactions() throws Exception {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("creditCard", "4111111111111111");

        AppendEventRequest request = new AppendEventRequest(
                "PAYMENT", "actor-pay", "PAYMENT", "p-1", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();

        int concurrency = 5;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Callable<RedactionResult>> tasks = new ArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            tasks.add(() -> redactionService.redact(
                    eventId, new RedactionRequest("creditCard", "PCI_DSS", "auditor-cc")));
        }

        List<Future<RedactionResult>> futures = executor.invokeAll(tasks, 15, TimeUnit.SECONDS);
        executor.shutdown();

        for (Future<RedactionResult> f : futures) {
            RedactionResult res = f.get();
            assertThat(res.status()).isEqualTo("COMPLETED");
            assertThat(res.fieldPath()).isEqualTo("creditCard");
        }

        // Verify only 1 meta-audit event exists for this operation
        Long metaCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event WHERE event_type = 'PAYLOAD_REDACTED' "
                + "AND payload->>'redactionOperationId' = ?",
                Long.class, "redact:" + eventId + ":creditCard");
        assertThat(metaCount).isEqualTo(1L);

        // Verify only 1 row in audit_event_redaction
        Long redactionRowCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event_redaction WHERE event_id = ?::uuid",
                Long.class, eventId.toString());
        assertThat(redactionRowCount).isEqualTo(1L);
    }

    @Test
    @DisplayName("Redaction fails with 404 when target event does not exist")
    void testNonexistentEventThrows() {
        UUID nonExistentId = UUID.randomUUID();
        RedactionRequest req = new RedactionRequest("accountNumber", "GDPR", "user");

        assertThatThrownBy(() -> redactionService.redact(nonExistentId, req))
                .isInstanceOf(AuditEventNotFoundException.class)
                .hasMessageContaining(nonExistentId.toString());
    }

    @Test
    @DisplayName("Redaction fails with 400 when field path is not present in payload")
    void testNonexistentFieldThrows() {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("action", "LOGOUT");

        AppendEventRequest request = new AppendEventRequest(
                "LOGOUT", "actor-1", "USER", "u-1", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);

        RedactionRequest req = new RedactionRequest("nonExistentField", "GDPR", "user");

        assertThatThrownBy(() -> redactionService.redact(appendResult.eventId(), req))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Field path 'nonExistentField' not found");
    }

    @Test
    @DisplayName("KMS failure during key destruction leaves state KEY_DESTRUCTION_FAILED and appends no meta-event")
    void testKeyDestructionFailure() {
        KeyManager failingKeyManager = new KeyManager() {
            @Override
            public javax.crypto.SecretKey generateKey(String keyId) { return null; }
            @Override
            public java.util.Optional<javax.crypto.SecretKey> getKey(String keyId) { return java.util.Optional.empty(); }
            @Override
            public boolean destroyKey(String keyId) {
                throw new RuntimeException("KMS connection refused");
            }
            @Override
            public boolean isKeyActive(String keyId) { return true; }
            @Override
            public boolean isKeyDestroyed(String keyId) { return false; }
        };

        AuditRedactionService serviceWithFailingKms = new AuditRedactionService(
                jdbcTemplate, coordinator, failingKeyManager, objectMapper);

        String keyId = "dek-failing-1";
        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, "my-confidential-data");

        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("sensitiveData", objectMapper.valueToTree(envelope));

        AppendEventRequest request = new AppendEventRequest(
                "DATA_SAVE", "actor-1", "DOC", "d-1", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();

        assertThatThrownBy(() -> serviceWithFailingKms.redact(
                eventId, new RedactionRequest("sensitiveData", "ERASURE", "officer")))
                .isInstanceOf(RedactionKeyDestructionException.class)
                .hasMessageContaining(keyId);

        // Verify status in DB is KEY_DESTRUCTION_FAILED
        String status = jdbcTemplate.queryForObject(
                "SELECT status FROM audit_event_redaction WHERE event_id = ?::uuid",
                String.class, eventId.toString());
        assertThat(status).isEqualTo("KEY_DESTRUCTION_FAILED");

        // Verify no PAYLOAD_REDACTED event was appended
        Long metaCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event WHERE event_type = 'PAYLOAD_REDACTED'", Long.class);
        assertThat(metaCount).isZero();
    }

    @Test
    @DisplayName("Independent concurrent transactions lock with SELECT FOR UPDATE and produce exactly one meta-event")
    void testConcurrentTransactionsSerializeAndDeduplicateMetaAudit() throws Exception {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("ssn", "000-11-2222");

        AppendEventRequest request = new AppendEventRequest(
                "ONBOARDING", "actor-txn", "USER", "u-txn", payload, Instant.now());
        AppendEventResult appendResult = appendService.append(request);
        UUID eventId = appendResult.eventId();
        String operationId = "redact:" + eventId + ":ssn";

        // Seed PENDING and transition to KEY_DESTROYED
        coordinator.ensurePendingRegistered(operationId, eventId, "ssn", "PRIVACY", "auditor", "MASKED", null);
        coordinator.updateStatus(operationId, "KEY_DESTROYED");

        int threadCount = 4;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Callable<RedactionResult>> tasks = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            tasks.add(() -> coordinator.lockAndFinalizeMetaAudit(
                    operationId,
                    eventId,
                    appendResult.sequenceNo(),
                    "USER",
                    "u-txn",
                    "ssn",
                    "PRIVACY",
                    "auditor",
                    "MASKED",
                    null));
        }

        List<Future<RedactionResult>> futures = executor.invokeAll(tasks, 15, TimeUnit.SECONDS);
        executor.shutdown();

        Long expectedSeq = null;
        for (Future<RedactionResult> f : futures) {
            RedactionResult res = f.get();
            assertThat(res.status()).isEqualTo("COMPLETED");
            if (expectedSeq == null) {
                expectedSeq = res.metaAuditSequenceNo();
            } else {
                assertThat(res.metaAuditSequenceNo()).isEqualTo(expectedSeq);
            }
        }

        // Exactly one PAYLOAD_REDACTED event must exist
        Long metaCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event WHERE event_type = 'PAYLOAD_REDACTED' "
                + "AND payload->>'redactionOperationId' = ?",
                Long.class, operationId);
        assertThat(metaCount).isEqualTo(1L);

        // Chain verification must be intact
        assertThat(verificationService.verifyChain().status()).isEqualTo("INTACT");
    }
}
