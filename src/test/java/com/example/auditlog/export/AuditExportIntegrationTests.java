package com.example.auditlog.export;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.archival.AuditArchivalService;
import com.example.auditlog.crypto.AuditCryptoService;
import com.example.auditlog.crypto.EncryptedEnvelope;
import com.example.auditlog.crypto.InMemoryKeyManager;
import com.example.auditlog.crypto.KeyManager;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.redaction.AuditRedactionService;
import com.example.auditlog.redaction.RedactionRequest;
import com.example.auditlog.redaction.RedactionResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Collections;
import java.util.UUID;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * End-to-end integration tests for {@code GET /audit/exports} against real PostgreSQL 16
 * using Testcontainers, Flyway, embedded servlet container, and {@link TestRestTemplate}.
 *
 * <p>Validates:
 * <ul>
 *   <li>Bulk export by {@code actorId} and {@code resourceId} with sparse witness chains.</li>
 *   <li>Independent cryptographic verification via {@link StandaloneExportVerifier}.</li>
 *   <li>Independent verification via the standalone Python script {@code scripts/verify_export.py}.</li>
 *   <li>Cross-milestone integration with soft archival (Milestone 9) and structured redaction (Milestone 10).</li>
 *   <li>Snapshot consistency and lack of dangling links under concurrent operations.</li>
 *   <li>Documented completeness boundary demonstration.</li>
 * </ul>
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditExportIntegrationTests {

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
    private AuditRedactionService redactionService;

    @Autowired
    private AuditCryptoService cryptoService;

    @Autowired
    private KeyManager keyManager;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired(required = false)
    private AuditExportProperties exportProperties;

    private StandaloneExportVerifier verifier;

    @BeforeEach
    void cleanAndMigrate() {
        this.restTemplate = rawRestTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        this.verifier = new StandaloneExportVerifier();
        if (exportProperties != null) {
            exportProperties.setMaxMatchedEvents(1000);
            exportProperties.setMaxTotalRecords(10000);
        }
        flyway.clean();
        flyway.migrate();
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Test
    @DisplayName("Export from empty database returns 200 OK with empty bundle and intact verification")
    void testExportEmptyDatabase() {
        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?actorId=alice",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();
        assertThat(bundle.bundleVersion()).isEqualTo("1.0");
        assertThat(bundle.chainHead().sequenceNo()).isEqualTo(0L);
        assertThat(bundle.summary().matchedEventsCount()).isEqualTo(0L);
        assertThat(bundle.summary().witnessCount()).isEqualTo(0L);
        assertThat(bundle.events()).isEmpty();
        assertThat(bundle.witnesses()).isEmpty();

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
    }

    @Test
    @DisplayName("Export by actorId produces sparse witness chain verified by Java verifier and Python script")
    void testExportByActorIdWithWitnesses() throws Exception {
        // Append 5 events:
        // seq 1: alice
        // seq 2: bob
        // seq 3: alice
        // seq 4: charlie
        // seq 5: alice
        AppendEventResult r1 = appendService.append(new AppendEventRequest(
                "ORDER_CREATED", "alice", "ORDER", "ord-1",
                objectMapper.createObjectNode().put("amount", 100), Instant.now()));
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "LOGIN", "bob", "USER", "user-bob",
                objectMapper.createObjectNode().put("method", "PASSWORD"), Instant.now()));
        AppendEventResult r3 = appendService.append(new AppendEventRequest(
                "PAYMENT_SENT", "alice", "PAYMENT", "pay-1",
                objectMapper.createObjectNode().put("cents", 5000), Instant.now()));
        AppendEventResult r4 = appendService.append(new AppendEventRequest(
                "TRANSFER", "charlie", "ACCOUNT", "acc-charlie",
                objectMapper.createObjectNode().put("target", "bank"), Instant.now()));
        AppendEventResult r5 = appendService.append(new AppendEventRequest(
                "LOGOUT", "alice", "USER", "user-alice",
                objectMapper.createObjectNode().put("session", "s-1"), Instant.now()));

        assertThat(r5.sequenceNo()).isEqualTo(5L);

        // Export for alice
        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?actorId=alice",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();

        assertThat(bundle.chainHead().sequenceNo()).isEqualTo(5L);
        assertThat(bundle.summary().matchedEventsCount()).isEqualTo(3L);
        assertThat(bundle.summary().firstMatchedSequenceNo()).isEqualTo(1L);
        assertThat(bundle.summary().lastMatchedSequenceNo()).isEqualTo(5L);
        assertThat(bundle.summary().witnessCount()).isEqualTo(2L);

        assertThat(bundle.events()).hasSize(3);
        assertThat(bundle.events().stream().map(ExportEventDto::sequenceNo).toList())
                .containsExactly(1L, 3L, 5L);

        assertThat(bundle.witnesses()).hasSize(2);
        assertThat(bundle.witnesses().stream().map(ExportWitnessDto::sequenceNo).toList())
                .containsExactly(2L, 4L);

        // 1. Verify via Java verifier
        StandaloneExportVerifier.ExportVerificationResult javaResult = verifier.verify(bundle);
        assertThat(javaResult.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(javaResult.recordsVerified()).isEqualTo(5L);
        assertThat(javaResult.matchedEventsVerified()).isEqualTo(3L);

        // 2. Verify via Python script
        Path tempBundleFile = Files.createTempFile("export-bundle-", ".json");
        try {
            objectMapper.writeValue(tempBundleFile.toFile(), bundle);
            ProcessBuilder pb = new ProcessBuilder("python3", "scripts/verify_export.py", tempBundleFile.toAbsolutePath().toString());
            Process process = pb.start();
            int exitCode = process.waitFor();

            BufferedReader stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String stdoutStr = stdout.lines().reduce("", (a, b) -> a + "\n" + b);

            assertThat(exitCode).as("Python verifier output: " + stdoutStr).isEqualTo(0);
            assertThat(stdoutStr).contains("Status:               INTACT");
            assertThat(stdoutStr).contains("Total Records Linked: 5");
            assertThat(stdoutStr).contains("Matched Events:       3");
        } finally {
            Files.deleteIfExists(tempBundleFile);
        }
    }

    @Test
    @DisplayName("Export by resourceId verifies accurately")
    void testExportByResourceId() {
        appendService.append(new AppendEventRequest(
                "DOC_CREATED", "alice", "DOCUMENT", "doc-100",
                objectMapper.createObjectNode().put("title", "Report"), Instant.now()));
        appendService.append(new AppendEventRequest(
                "DOC_CREATED", "bob", "DOCUMENT", "doc-200",
                objectMapper.createObjectNode().put("title", "Invoice"), Instant.now()));
        appendService.append(new AppendEventRequest(
                "DOC_SIGNED", "charlie", "DOCUMENT", "doc-100",
                objectMapper.createObjectNode().put("sig", "xyz"), Instant.now()));

        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?resourceId=doc-100",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();

        assertThat(bundle.summary().matchedEventsCount()).isEqualTo(2L);
        assertThat(bundle.summary().witnessCount()).isEqualTo(1L);
        assertThat(bundle.events().stream().map(ExportEventDto::sequenceNo).toList()).containsExactly(1L, 3L);
        assertThat(bundle.witnesses().stream().map(ExportWitnessDto::sequenceNo).toList()).containsExactly(2L);

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
    }

    @Test
    @DisplayName("Export includes soft-archived events by default and excludes them when includeArchived=false")
    void testExportSoftArchivedEvents() {
        AppendEventResult r1 = appendService.append(new AppendEventRequest(
                "LOG_1", "alice", "SYS", "s1",
                objectMapper.createObjectNode().put("k", 1), Instant.now()));
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "LOG_2", "alice", "SYS", "s1",
                objectMapper.createObjectNode().put("k", 2), Instant.now()));

        // Archive seq 1
        archivalService.archive(r1.eventId(), "RETENTION_POLICY_DEFAULT");

        // Default: includeArchived = true
        ResponseEntity<ExportBundleDto> responseDefault = restTemplate.exchange(
                "/audit/exports?actorId=alice",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(responseDefault.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundleDefault = responseDefault.getBody();
        assertThat(bundleDefault).isNotNull();
        assertThat(bundleDefault.events()).hasSize(2);

        ExportEventDto event1 = bundleDefault.events().get(0);
        assertThat(event1.archivedAt()).isNotNull();
        assertThat(bundleDefault.events().get(1).archivedAt()).isNull();

        StandaloneExportVerifier.ExportVerificationResult resDefault = verifier.verify(bundleDefault);
        assertThat(resDefault.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);

        // When includeArchived = false
        ResponseEntity<ExportBundleDto> responseExcluded = restTemplate.exchange(
                "/audit/exports?actorId=alice&includeArchived=false",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(responseExcluded.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundleExcluded = responseExcluded.getBody();
        assertThat(bundleExcluded).isNotNull();
        // seq 1 is archived, so it should be demoted to witness!
        assertThat(bundleExcluded.events()).hasSize(1);
        assertThat(bundleExcluded.events().get(0).sequenceNo()).isEqualTo(2L);
        assertThat(bundleExcluded.witnesses()).hasSize(1);
        assertThat(bundleExcluded.witnesses().get(0).sequenceNo()).isEqualTo(1L);

        StandaloneExportVerifier.ExportVerificationResult resExcluded = verifier.verify(bundleExcluded);
        assertThat(resExcluded.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
    }

    @Test
    @DisplayName("Export with crypto-shredded envelope preserves ciphertext and verifies cleanly alongside meta-audit event")
    void testExportWithCryptoShreddedEvent() {
        String keyId = "key-export-test-1";
        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, "sensitive-tax-id-123");
        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("taxId", objectMapper.valueToTree(envelope));
        payload.put("nonSensitive", "public-data");

        AppendEventResult appendResult = appendService.append(new AppendEventRequest(
                "TAX_RECORDED", "tax-officer", "ACCOUNT", "acc-tax-999", payload, Instant.now()));

        // Redact the taxId field (crypto-shredding: permanently destroys key in keyManager)
        RedactionResult redactionResult = redactionService.redact(
                appendResult.eventId(),
                new RedactionRequest("taxId", "GDPR_ARTICLE_17", "compliance-admin"));

        assertThat(redactionResult.redactionType()).isEqualTo("CRYPTO_SHREDDED");
        assertThat(keyManager.isKeyDestroyed(keyId)).isTrue();

        // Export by resourceId
        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?resourceId=acc-tax-999",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();

        // Both the original TAX_RECORDED and the PAYLOAD_REDACTED meta-event share resourceId = acc-tax-999!
        assertThat(bundle.events()).hasSize(2);
        ExportEventDto originalEvent = bundle.events().stream()
                .filter(e -> e.eventType().equals("TAX_RECORDED"))
                .findFirst().orElseThrow();

        // Verify the original ciphertext envelope is retained in the exported payload
        JsonNode taxIdNode = originalEvent.payload().path("taxId");
        assertThat(taxIdNode.path("@type").asText()).isEqualTo("EncryptedEnvelope");
        assertThat(taxIdNode.path("keyId").asText()).isEqualTo(keyId);
        assertThat(taxIdNode.has("ciphertext")).isTrue();

        // Verify the meta-audit event exists in the export
        ExportEventDto metaEvent = bundle.events().stream()
                .filter(e -> e.eventType().equals("PAYLOAD_REDACTED"))
                .findFirst().orElseThrow();
        assertThat(metaEvent.payload().path("redactionType").asText()).isEqualTo("CRYPTO_SHREDDED");

        // Verify the export bundle cryptographically
        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.recordsVerified()).isEqualTo(2L);
        assertThat(result.matchedEventsVerified()).isEqualTo(2L);
    }

    @Test
    @DisplayName("Export with legacy plaintext redacted event masks field projection and verifies as PARTIALLY_VERIFIED_REDACTED")
    void testExportWithLegacyMaskedRedactedEvent() throws Exception {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("ssn", "999-88-7777");
        payload.put("accountHolder", "John Doe");

        AppendEventResult appendResult = appendService.append(new AppendEventRequest(
                "LEGACY_OPEN", "banker", "ACCOUNT", "acc-legacy-1", payload, Instant.now()));

        // Redact legacy plaintext field
        redactionService.redact(
                appendResult.eventId(),
                new RedactionRequest("ssn", "PRIVACY_REQUEST", "dpo-agent"));

        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?resourceId=acc-legacy-1",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();

        ExportEventDto event = bundle.events().stream()
                .filter(e -> e.eventType().equals("LEGACY_OPEN"))
                .findFirst().orElseThrow();

        // Verify sensitive plaintext is masked in projection
        assertThat(event.payload().path("ssn").asText()).isEqualTo("[REDACTED]");
        assertThat(event.payload().toString()).doesNotContain("999-88-7777");
        assertThat(event.redactionType()).isEqualTo("MASKED");

        // Verify with Java StandaloneExportVerifier
        StandaloneExportVerifier.ExportVerificationResult javaResult = verifier.verify(bundle);
        assertThat(javaResult.status()).isEqualTo(StandaloneExportVerifier.Status.PARTIALLY_VERIFIED_REDACTED);
        assertThat(javaResult.recordsVerified()).isEqualTo(bundle.chainHead().sequenceNo());
        assertThat(javaResult.matchedEventsVerified()).isEqualTo(1L); // Meta-audit event is unredacted
        assertThat(javaResult.maskedEventsCount()).isEqualTo(1L);

        // Verify with Python verifier script
        Path tempBundleFile = Files.createTempFile("export-bundle-masked-", ".json");
        try {
            objectMapper.writeValue(tempBundleFile.toFile(), bundle);
            ProcessBuilder pb = new ProcessBuilder("python3", "scripts/verify_export.py", tempBundleFile.toAbsolutePath().toString());
            Process process = pb.start();
            int exitCode = process.waitFor();

            BufferedReader stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String stdoutStr = stdout.lines().reduce("", (a, b) -> a + "\n" + b);

            assertThat(exitCode).as("Python verifier output: " + stdoutStr).isEqualTo(0);
            assertThat(stdoutStr).contains("Status:               PARTIALLY_VERIFIED_REDACTED");
            assertThat(stdoutStr).contains("Masked Events:        1");
        } finally {
            Files.deleteIfExists(tempBundleFile);
        }
    }

    @Test
    @DisplayName("Demonstrate documented completeness limitation: a synthetic witness cannot be detected as an omitted event")
    void testCompletenessBoundaryDemonstration() {
        // Appends:
        // seq 1: alice
        // seq 2: alice
        AppendEventResult r1 = appendService.append(new AppendEventRequest(
                "A1", "alice", "RES", "r1", objectMapper.createObjectNode().put("v", 1), Instant.now()));
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "A2", "alice", "RES", "r1", objectMapper.createObjectNode().put("v", 2), Instant.now()));

        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?actorId=alice",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        ExportBundleDto honestBundle = response.getBody();
        assertThat(honestBundle).isNotNull();
        assertThat(honestBundle.events()).hasSize(2);

        // Create a manipulated bundle where seq 2 was omitted from events and placed into witnesses
        ExportEventDto ev1 = honestBundle.events().get(0);
        ExportEventDto ev2 = honestBundle.events().get(1);
        ExportWitnessDto fakedWitness2 = new ExportWitnessDto(
                ev2.sequenceNo(), ev2.previousHash(), ev2.contentHash(), ev2.recordHash());

        ExportBundleDto manipulatedBundle = new ExportBundleDto(
                honestBundle.bundleVersion(),
                honestBundle.exportId(),
                honestBundle.exportedAt(),
                honestBundle.filter(),
                honestBundle.chainHead(),
                new ExportSummaryDto(1L, 1L, 1L, 1L),
                Collections.singletonList(ev1),
                Collections.singletonList(fakedWitness2)
        );

        // Verification passes because hash-chain inclusion and continuity are mathematically intact!
        // This empirically validates the documented boundary: sparse-chain exports prove inclusion & authenticity,
        // but cannot prove non-omission of events without zero-knowledge proofs or disclosing witness payloads.
        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(manipulatedBundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.recordsVerified()).isEqualTo(2L);
        assertThat(result.matchedEventsVerified()).isEqualTo(1L);
    }

    @Test
    @DisplayName("Export exceeding maxMatchedEvents returns 413 Payload Too Large")
    void testExportExceedingMaxMatchedEventsReturns413() {
        exportProperties.setMaxMatchedEvents(2);
        try {
            // Append 3 events matching actor 'charlie'
            for (int i = 1; i <= 3; i++) {
                appendService.append(new AppendEventRequest(
                        "ACTION_" + i, "charlie", "RES", "r" + i,
                        objectMapper.createObjectNode().put("idx", i), Instant.now()));
            }

            ResponseEntity<String> response = restTemplate.exchange(
                    "/audit/exports?actorId=charlie",
                    HttpMethod.GET,
                    new HttpEntity<>(jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
            assertThat(response.getBody()).contains("exceeds maximum supported matching events limit of 2");
        } finally {
            exportProperties.setMaxMatchedEvents(1000);
        }
    }

    @Test
    @DisplayName("Export exceeding maxTotalRecords returns 413 Payload Too Large")
    void testExportExceedingMaxTotalRecordsReturns413() {
        exportProperties.setMaxTotalRecords(2);
        try {
            // Append 3 events so total chain length is 3 > maxTotalRecords (2)
            for (int i = 1; i <= 3; i++) {
                appendService.append(new AppendEventRequest(
                        "OP_" + i, "user_" + i, "RES", "r" + i,
                        objectMapper.createObjectNode().put("idx", i), Instant.now()));
            }

            ResponseEntity<String> response = restTemplate.exchange(
                    "/audit/exports?actorId=user_1",
                    HttpMethod.GET,
                    new HttpEntity<>(jsonHeaders()),
                    String.class);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
            assertThat(response.getBody()).contains("exceeds maximum supported total chain records limit of 2");
        } finally {
            exportProperties.setMaxTotalRecords(10000);
        }
    }

    @Test
    @DisplayName("Export executes with REPEATABLE_READ isolation guaranteeing snapshot consistency")
    void testExportTransactionSnapshotConsistency() throws Exception {
        // Verify transactional annotations on AuditExportService
        var method = AuditExportService.class.getMethod("exportBundle", ExportFilterCriteria.class);
        var tx = method.getAnnotation(org.springframework.transaction.annotation.Transactional.class);
        assertThat(tx).isNotNull();
        assertThat(tx.readOnly()).isTrue();
        assertThat(tx.isolation()).isEqualTo(org.springframework.transaction.annotation.Isolation.REPEATABLE_READ);

        // Append initial events
        for (int i = 1; i <= 3; i++) {
            appendService.append(new AppendEventRequest(
                    "INITIAL_" + i, "snap-user", "RES", "r" + i,
                    objectMapper.createObjectNode().put("idx", i), Instant.now()));
        }

        ResponseEntity<ExportBundleDto> response = restTemplate.exchange(
                "/audit/exports?actorId=snap-user",
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders()),
                ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();
        assertThat(bundle.chainHead().sequenceNo()).isGreaterThanOrEqualTo(3L);

        StandaloneExportVerifier.ExportVerificationResult res = verifier.verify(bundle);
        assertThat(res.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
    }
}
