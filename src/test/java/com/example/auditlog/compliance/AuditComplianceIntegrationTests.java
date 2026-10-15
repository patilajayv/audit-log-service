package com.example.auditlog.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.archival.AuditArchivalService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.export.StandaloneExportVerifier;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.redaction.AuditRedactionService;
import com.example.auditlog.redaction.RedactionRequest;
import com.example.auditlog.redaction.RedactionResult;
import com.example.auditlog.verify.AuditVerificationResponse;
import com.fasterxml.jackson.core.type.TypeReference;
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
import java.util.Collections;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
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
 * End-to-end integration tests for Scenario C compliance reporting and regulator auditing.
 *
 * <p>Validates:
 * <ul>
 *   <li>Mandatory account scoping and server-side isolation from non-account resources.</li>
 *   <li>Fail-closed supervisory auditing ({@code REGULATORY_AUDIT_ACCESSED} and {@code REGULATORY_EXPORT_ACCESSED}).</li>
 *   <li>Exclusion of supervisory events from account queries (preventing feedback loops and pagination drift).</li>
 *   <li>Preservation of full-chain verification ({@code GET /audit/verify}) across business and supervisory records.</li>
 *   <li>Constrained export generation with independent Java and Python verifier compatibility.</li>
 *   <li>Soft-archival default inclusion and structured redaction projection masking.</li>
 * </ul>
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditComplianceIntegrationTests {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("audit_log")
            .withUsername("audit_migrator")
            .withPassword("migrator_secret");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement stmt = conn.createStatement()) {
            stmt.execute("DO $$ BEGIN "
                    + "IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'audit_app') THEN "
                    + "CREATE ROLE audit_app LOGIN PASSWORD 'local-development-password'; "
                    + "END IF; "
                    + "END $$;");
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize test database roles", e);
        }
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.flyway.clean-disabled", () -> "false");
    }

    @Autowired
    private TestRestTemplate rawRestTemplate;

    private TestRestTemplate regulatorTemplate;
    private TestRestTemplate auditorTemplate;

    @Autowired
    private AuditAppendService appendService;

    @Autowired
    private AuditArchivalService archivalService;

    @Autowired
    private AuditRedactionService redactionService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    private StandaloneExportVerifier verifier;

    @BeforeEach
    void cleanAndMigrate() {
        this.regulatorTemplate = rawRestTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        this.auditorTemplate = rawRestTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        this.verifier = new StandaloneExportVerifier();
        flyway.clean();
        flyway.migrate();
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Test
    @DisplayName("Query account access isolates by accountId and resourceType = ACCOUNT, omitting other accounts and resources")
    void testQueryAccountAccessFiltersByAccountAndResourceType() {
        // Seed event 1: Account ACC-100 view
        ObjectNode p1 = objectMapper.createObjectNode();
        p1.put("accessType", "VIEW");
        p1.put("actorRole", "WEALTH_ADVISOR");
        AppendEventResult r1 = appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "advisor-1", "ACCOUNT", "ACC-100", p1, null));

        // Seed event 2: Account ACC-100 statement download
        ObjectNode p2 = objectMapper.createObjectNode();
        p2.put("accessType", "DOWNLOAD");
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "STATEMENT_DOWNLOADED", "advisor-1", "ACCOUNT", "ACC-100", p2, null));

        // Seed event 3: Account ACC-200 view (different account)
        ObjectNode p3 = objectMapper.createObjectNode();
        p3.put("accessType", "VIEW");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "advisor-2", "ACCOUNT", "ACC-200", p3, null));

        // Seed event 4: Config change with resourceId = ACC-100 but resourceType = SYSTEM_CONFIG
        ObjectNode p4 = objectMapper.createObjectNode();
        p4.put("param", "LIMIT");
        appendService.append(new AppendEventRequest(
                "CONFIG_UPDATED", "admin-1", "SYSTEM_CONFIG", "ACC-100", p4, null));

        // Initial event count in audit_event: 4
        Integer preQueryCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Integer.class);
        assertThat(preQueryCount).isEqualTo(4);

        // Execute compliance query as REGULATOR
        ResponseEntity<String> response = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-100", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        AuditPageResponse<AuditEventDto> page = deserializePage(response.getBody());
        assertThat(page.events()).hasSize(2);
        assertThat(page.events().get(0).sequenceNo()).isEqualTo(r1.sequenceNo());
        assertThat(page.events().get(0).resourceType()).isEqualTo("ACCOUNT");
        assertThat(page.events().get(0).resourceId()).isEqualTo("ACC-100");
        assertThat(page.events().get(0).eventType()).isEqualTo("ACCOUNT_VIEWED");

        assertThat(page.events().get(1).sequenceNo()).isEqualTo(r2.sequenceNo());
        assertThat(page.events().get(1).resourceType()).isEqualTo("ACCOUNT");
        assertThat(page.events().get(1).resourceId()).isEqualTo("ACC-100");
        assertThat(page.events().get(1).eventType()).isEqualTo("STATEMENT_DOWNLOADED");

        // Verify supervisory audit record was committed
        Integer postQueryCount = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_event", Integer.class);
        assertThat(postQueryCount).isEqualTo(5); // 4 business + 1 supervisory

        List<String> eventTypes = jdbcTemplate.queryForList(
                "SELECT event_type FROM audit_event WHERE sequence_no = 5", String.class);
        assertThat(eventTypes).containsExactly("REGULATORY_AUDIT_ACCESSED");

        String supervisoryResource = jdbcTemplate.queryForObject(
                "SELECT resource_type FROM audit_event WHERE sequence_no = 5", String.class);
        assertThat(supervisoryResource).isEqualTo("COMPLIANCE_AUDIT");

        // Second query: Verify supervisory record does NOT appear in account query results (loop prevention)
        ResponseEntity<String> secondResponse = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-100", String.class);
        AuditPageResponse<AuditEventDto> secondPage = deserializePage(secondResponse.getBody());
        assertThat(secondPage.events()).hasSize(2); // Still strictly 2!
        assertThat(secondPage.events().stream().map(AuditEventDto::eventType))
                .doesNotContain("REGULATORY_AUDIT_ACCESSED");
    }

    @Test
    @DisplayName("Query includes soft-archived account events by default and excludes them when includeArchived=false")
    void testQueryIncludesSoftArchivedEventsByDefault() {
        ObjectNode p1 = objectMapper.createObjectNode();
        p1.put("accessType", "VIEW");
        AppendEventResult r1 = appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "teller-1", "ACCOUNT", "ACC-777", p1, null));

        ObjectNode p2 = objectMapper.createObjectNode();
        p2.put("accessType", "DOWNLOAD");
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "STATEMENT_DOWNLOADED", "teller-1", "ACCOUNT", "ACC-777", p2, null));

        // Soft-archive event 1
        archivalService.archive(r1.eventId(), "RETENTION_POLICY");

        // Query with default includeArchived (true)
        ResponseEntity<String> defaultResp = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-777", String.class);
        AuditPageResponse<AuditEventDto> defaultPage = deserializePage(defaultResp.getBody());
        assertThat(defaultPage.events()).hasSize(2);
        assertThat(defaultPage.events().get(0).archivedAt()).isNotNull();
        assertThat(defaultPage.events().get(1).archivedAt()).isNull();

        // Query with includeArchived=false
        ResponseEntity<String> falseResp = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-777&includeArchived=false", String.class);
        AuditPageResponse<AuditEventDto> falsePage = deserializePage(falseResp.getBody());
        assertThat(falsePage.events()).hasSize(1);
        assertThat(falsePage.events().get(0).sequenceNo()).isEqualTo(r2.sequenceNo());
    }

    @Test
    @DisplayName("Query with optional filters (eventType, actorId) filters matching account events")
    void testQueryWithOptionalFilters() {
        ObjectNode p1 = objectMapper.createObjectNode();
        p1.put("action", "SEARCH");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_SEARCHED", "rep-10", "ACCOUNT", "ACC-500", p1, null));

        ObjectNode p2 = objectMapper.createObjectNode();
        p2.put("action", "VIEW");
        AppendEventResult r2 = appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "rep-20", "ACCOUNT", "ACC-500", p2, null));

        ResponseEntity<String> resp = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-500&actorId=rep-20&eventType=ACCOUNT_VIEWED",
                String.class);

        AuditPageResponse<AuditEventDto> page = deserializePage(resp.getBody());
        assertThat(page.events()).hasSize(1);
        assertThat(page.events().get(0).sequenceNo()).isEqualTo(r2.sequenceNo());
        assertThat(page.events().get(0).actorId()).isEqualTo("rep-20");
    }

    @Test
    @DisplayName("Compliance export produces self-contained bundle verifying via Java and Python verifiers")
    void testComplianceExportAndVerifiers() throws Exception {
        ObjectNode p1 = objectMapper.createObjectNode();
        p1.put("accessType", "VIEW");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "advisor-1", "ACCOUNT", "ACC-999", p1, null));

        // Interleaved event for another account
        ObjectNode p2 = objectMapper.createObjectNode();
        p2.put("accessType", "VIEW");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "advisor-2", "ACCOUNT", "ACC-888", p2, null));

        ObjectNode p3 = objectMapper.createObjectNode();
        p3.put("accessType", "EXPORT");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_EXPORTED", "advisor-1", "ACCOUNT", "ACC-999", p3, null));

        // Call compliance export endpoint
        ResponseEntity<ExportBundleDto> response = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access/export?accountId=ACC-999", ExportBundleDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExportBundleDto bundle = response.getBody();
        assertThat(bundle).isNotNull();
        assertThat(bundle.filter().filterType()).isEqualTo("RESOURCE_ID");
        assertThat(bundle.filter().filterValue()).isEqualTo("ACC-999");
        assertThat(bundle.summary().matchedEventsCount()).isEqualTo(2);

        // Verify with Java StandaloneExportVerifier
        var result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.matchedEventsVerified()).isEqualTo(2);

        // Verify with Python standalone verifier scripts/verify_export.py
        verifyWithPythonScript(objectMapper.writeValueAsString(bundle));

        // Verify supervisory export record was committed
        List<String> exportEvents = jdbcTemplate.queryForList(
                "SELECT event_type FROM audit_event WHERE event_type = 'REGULATORY_EXPORT_ACCESSED'",
                String.class);
        assertThat(exportEvents).hasSize(1);
    }

    @Test
    @DisplayName("Complete chain verification (/audit/verify) remains INTACT after supervisory query and export events")
    void testFullChainVerificationIntactAfterComplianceOperations() {
        ObjectNode p1 = objectMapper.createObjectNode();
        p1.put("accessType", "VIEW");
        appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "advisor-1", "ACCOUNT", "ACC-101", p1, null));

        // Run compliance query
        regulatorTemplate.getForEntity("/audit/compliance/account-access?accountId=ACC-101", String.class);

        // Run compliance export
        regulatorTemplate.getForEntity("/audit/compliance/account-access/export?accountId=ACC-101", ExportBundleDto.class);

        // As internal auditor, verify the full chain
        ResponseEntity<AuditVerificationResponse> verifyResp = auditorTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(verifyResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(verifyResp.getBody()).isNotNull();
        assertThat(verifyResp.getBody().status()).isEqualTo("INTACT");
        // Records verified: 1 business event + 1 supervisory query + 1 supervisory export = 3 records
        assertThat(verifyResp.getBody().recordsVerified()).isEqualTo(3L);
        assertThat(verifyResp.getBody().violation()).isNull();
    }

    @Test
    @DisplayName("Compliance query preserves structured redaction projection masking for account events")
    void testRedactedAccountEventDisplaysMaskedProjection() {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("accessType", "VIEW");
        payload.put("taxId", "999-00-1111");

        AppendEventResult appendResult = appendService.append(new AppendEventRequest(
                "ACCOUNT_VIEWED", "teller-5", "ACCOUNT", "ACC-303", payload, null));

        // Redact the sensitive field
        RedactionResult redResult = redactionService.redact(
                appendResult.eventId(), new RedactionRequest("taxId", "GDPR_PRIVACY", "compliance-officer"));
        assertThat(redResult.status()).isEqualTo("COMPLETED");

        // Query via compliance endpoint
        ResponseEntity<String> response = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-303", String.class);

        AuditPageResponse<AuditEventDto> page = deserializePage(response.getBody());
        assertThat(page.events()).hasSize(2);
        AuditEventDto viewedEvent = page.events().get(0);
        assertThat(viewedEvent.eventType()).isEqualTo("ACCOUNT_VIEWED");
        assertThat(viewedEvent.payload().get("taxId").asText()).isEqualTo("[REDACTED]");
        assertThat(viewedEvent.payload().get("accessType").asText()).isEqualTo("VIEW");

        AuditEventDto metaEvent = page.events().get(1);
        assertThat(metaEvent.eventType()).isEqualTo("PAYLOAD_REDACTED");
        assertThat(metaEvent.payload().get("fieldPath").asText()).isEqualTo("taxId");
    }

    private AuditPageResponse<AuditEventDto> deserializePage(String json) {
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize page response", e);
        }
    }

    private void verifyWithPythonScript(String bundleJson) throws Exception {
        Path tempFile = Files.createTempFile("compliance_export_test_", ".json");
        try {
            Files.writeString(tempFile, bundleJson);
            File scriptFile = new File("scripts/verify_export.py");
            assertThat(scriptFile).exists();

            ProcessBuilder pb = new ProcessBuilder("python3", scriptFile.getAbsolutePath(), tempFile.toAbsolutePath().toString());
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            assertThat(exitCode)
                    .withFailMessage("Python verification failed with output: " + output)
                    .isEqualTo(0);
            assertThat(output.toString()).contains("Status:").contains("INTACT");
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}
