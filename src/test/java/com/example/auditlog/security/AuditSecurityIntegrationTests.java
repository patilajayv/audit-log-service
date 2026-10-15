package com.example.auditlog.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.api.AuditEventResponse;
import com.example.auditlog.api.ErrorResponse;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.verify.AuditVerificationResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
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
 * End-to-end integration tests for authentication, authorization, and least-privilege role separation.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Stateless HTTP Basic authentication enforcement on all endpoints</li>
 *   <li>Role separation: {@code AUDIT_WRITER} can append but not query or verify</li>
 *   <li>Role separation: {@code AUDITOR} can query and verify but not append</li>
 *   <li>Sanitized 401 Unauthorized with {@code WWW-Authenticate: Basic realm="AuditLogService"}</li>
 *   <li>Sanitized 403 Forbidden without WWW-Authenticate header</li>
 *   <li>Default deny on unmapped endpoints</li>
 *   <li>Database immutability invariant: rejected requests do not mutate audit records or chain-head</li>
 * </ul>
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "audit.rate-limit.ip-burst-capacity=1000",
                "audit.rate-limit.principal-burst-capacity=1000"
        }
)
class AuditSecurityIntegrationTests {

    private static final String VALID_EVENT_JSON = """
            {
                "eventType": "AUTH_LOGIN",
                "actorId": "security-user-1",
                "resourceType": "PORTAL",
                "resourceId": "portal-main",
                "payload": {"method": "CERTIFICATE"}
            }
            """;

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
    private TestRestTemplate restTemplate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ApplicationContext applicationContext;

    @BeforeEach
    void cleanAndMigrate() {
        flyway.clean();
        flyway.migrate();
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    // =========================================================================
    // POST /audit/events Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("POST /audit/events without authentication returns 401 with WWW-Authenticate header")
    void postEvents_unauthenticated_returns401() {
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
                "/audit/events", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
        assertThat(response.getBody().error()).isEqualTo("Unauthorized");
        assertThat(response.getBody().message()).contains("Full authentication is required");
    }

    @Test
    @DisplayName("POST /audit/events with invalid password returns 401 with WWW-Authenticate header")
    void postEvents_invalidCredentials_returns401() {
        TestRestTemplate badAuthTemplate = restTemplate.withBasicAuth("test-writer", "wrong-password");
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        ResponseEntity<ErrorResponse> response = badAuthTemplate.postForEntity(
                "/audit/events", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
    }

    @Test
    @DisplayName("POST /audit/events with AUDITOR role returns 403 Forbidden without WWW-Authenticate header")
    void postEvents_auditorRole_returns403() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        ResponseEntity<ErrorResponse> response = auditorTemplate.postForEntity(
                "/audit/events", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(403);
        assertThat(response.getBody().error()).isEqualTo("Forbidden");
        assertThat(response.getBody().message()).contains("Access is denied: insufficient role privileges");
    }

    @Test
    @DisplayName("POST /audit/events with AUDIT_WRITER role succeeds with 201 Created")
    void postEvents_writerRole_returns201() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        ResponseEntity<AuditEventResponse> response = writerTemplate.postForEntity(
                "/audit/events", request, AuditEventResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().sequenceNo()).isEqualTo(1L);
    }

    // =========================================================================
    // GET /audit/events Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("GET /audit/events without authentication returns 401 with WWW-Authenticate header")
    void getEvents_unauthenticated_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/audit/events", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
    }

    @Test
    @DisplayName("GET /audit/events with AUDIT_WRITER role returns 403 Forbidden")
    void getEvents_writerRole_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/audit/events", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(403);
        assertThat(response.getBody().error()).isEqualTo("Forbidden");
    }

    @Test
    @DisplayName("GET /audit/events with AUDITOR role succeeds with 200 OK")
    void getEvents_auditorRole_returns200() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        ResponseEntity<AuditPageResponse> response = auditorTemplate.getForEntity(
                "/audit/events", AuditPageResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
    }

    // =========================================================================
    // GET /audit/verify Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("GET /audit/verify without authentication returns 401 with WWW-Authenticate header")
    void getVerify_unauthenticated_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/audit/verify", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
    }

    @Test
    @DisplayName("GET /audit/verify with AUDIT_WRITER role returns 403 Forbidden")
    void getVerify_writerRole_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/audit/verify", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(403);
    }

    @Test
    @DisplayName("GET /audit/verify with AUDITOR role succeeds with 200 OK")
    void getVerify_auditorRole_returns200() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        ResponseEntity<AuditVerificationResponse> response = auditorTemplate.getForEntity(
                "/audit/verify", AuditVerificationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo("INTACT");
    }

    // =========================================================================
    // POST /audit/archive/** Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("POST /audit/archive/{eventId} without authentication returns 401 with WWW-Authenticate header")
    void postArchiveSingle_unauthenticated_returns401() {
        HttpEntity<String> request = new HttpEntity<>("{\"policyRef\":\"manual\"}", jsonHeaders());
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
                "/audit/archive/" + UUID.randomUUID(), request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("POST /audit/archive/{eventId} with AUDITOR role returns 403 Forbidden")
    void postArchiveSingle_auditorRole_returns403() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        HttpEntity<String> request = new HttpEntity<>("{\"policyRef\":\"manual\"}", jsonHeaders());
        ResponseEntity<ErrorResponse> response = auditorTemplate.postForEntity(
                "/audit/archive/" + UUID.randomUUID(), request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
    }

    @Test
    @DisplayName("POST /audit/archive/eligible without authentication returns 401")
    void postArchiveEligible_unauthenticated_returns401() {
        HttpEntity<String> request = new HttpEntity<>("{\"policyRef\":\"default-90d\"}", jsonHeaders());
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
                "/audit/archive/eligible", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("POST /audit/archive/eligible with AUDITOR role returns 403 Forbidden")
    void postArchiveEligible_auditorRole_returns403() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        HttpEntity<String> request = new HttpEntity<>("{\"policyRef\":\"default-90d\"}", jsonHeaders());
        ResponseEntity<ErrorResponse> response = auditorTemplate.postForEntity(
                "/audit/archive/eligible", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("POST /audit/archive/eligible with AUDIT_WRITER role succeeds with 200 OK")
    void postArchiveEligible_writerRole_returns200() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        HttpEntity<String> request = new HttpEntity<>("{\"policyRef\":\"default-90d\"}", jsonHeaders());
        ResponseEntity<Map> response = writerTemplate.postForEntity(
                "/audit/archive/eligible", request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("archivedCount")).isNotNull();
    }

    // =========================================================================
    // POST /audit/events/{eventId}/redact Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact without authentication returns 401 with WWW-Authenticate header")
    void postRedact_unauthenticated_returns401() {
        HttpEntity<String> request = new HttpEntity<>("""
                {
                  "fieldPath": "accountNumber",
                  "reason": "GDPR",
                  "requestedBy": "officer-1"
                }
                """, jsonHeaders());
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
                "/audit/events/" + UUID.randomUUID() + "/redact", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact with AUDITOR role returns 403 Forbidden")
    void postRedact_auditorRole_returns403() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        HttpEntity<String> request = new HttpEntity<>("""
                {
                  "fieldPath": "accountNumber",
                  "reason": "GDPR",
                  "requestedBy": "officer-1"
                }
                """, jsonHeaders());
        ResponseEntity<ErrorResponse> response = auditorTemplate.postForEntity(
                "/audit/events/" + UUID.randomUUID() + "/redact", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
    }

    @Test
    @DisplayName("POST /audit/events/{eventId}/redact with AUDIT_WRITER role passes security check")
    void postRedact_writerRole_authorized() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        UUID nonExistentId = UUID.randomUUID();
        HttpEntity<String> request = new HttpEntity<>("""
                {
                  "fieldPath": "accountNumber",
                  "reason": "GDPR",
                  "requestedBy": "officer-1"
                }
                """, jsonHeaders());
        ResponseEntity<ErrorResponse> response = writerTemplate.postForEntity(
                "/audit/events/" + nonExistentId + "/redact", request, ErrorResponse.class);

        // Security check passed (not 401 or 403); reaches controller logic and returns 404 Not Found
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // =========================================================================
    // Default Deny on Unmapped Endpoints
    // =========================================================================

    @Test
    @DisplayName("Unmapped route returns 401 when anonymous")
    void unmappedRoute_anonymous_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/nonexistent-endpoint", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("Unmapped route returns 403 when authenticated with any role")
    void unmappedRoute_authenticated_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/nonexistent-endpoint", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(403);
    }

    // =========================================================================
    // GET /audit/exports Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("GET /audit/exports without authentication returns 401 with WWW-Authenticate header")
    void getExports_unauthenticated_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/audit/exports?actorId=alice", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("GET /audit/exports with AUDIT_WRITER role returns 403 Forbidden without WWW-Authenticate header")
    void getExports_writerRole_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/audit/exports?actorId=alice", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(403);
    }

    @Test
    @DisplayName("GET /audit/exports with AUDITOR role succeeds with 200 OK")
    void getExports_auditorRole_returns200() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        ResponseEntity<String> response = auditorTemplate.getForEntity(
                "/audit/exports?actorId=alice", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // =========================================================================
    // GET /audit/compliance/account-access Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("GET /audit/compliance/account-access without authentication returns 401 with WWW-Authenticate header")
    void getComplianceAccountAccess_unauthenticated_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-1", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access with AUDIT_WRITER role returns 403 Forbidden")
    void getComplianceAccountAccess_writerRole_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-1", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access with AUDITOR role succeeds with 200 OK")
    void getComplianceAccountAccess_auditorRole_returns200() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        ResponseEntity<String> response = auditorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-1", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access with REGULATOR role succeeds with 200 OK")
    void getComplianceAccountAccess_regulatorRole_returns200() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<String> response = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access?accountId=ACC-1", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // =========================================================================
    // GET /audit/compliance/account-access/export Authentication & Authorization
    // =========================================================================

    @Test
    @DisplayName("GET /audit/compliance/account-access/export without authentication returns 401 with WWW-Authenticate header")
    void getComplianceExport_unauthenticated_returns401() {
        ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
                "/audit/compliance/account-access/export?accountId=ACC-1", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"AuditLogService\"");
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access/export with AUDIT_WRITER role returns 403 Forbidden")
    void getComplianceExport_writerRole_returns403() {
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> response = writerTemplate.getForEntity(
                "/audit/compliance/account-access/export?accountId=ACC-1", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access/export with AUDITOR role succeeds with 200 OK")
    void getComplianceExport_auditorRole_returns200() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");
        ResponseEntity<String> response = auditorTemplate.getForEntity(
                "/audit/compliance/account-access/export?accountId=ACC-1", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("GET /audit/compliance/account-access/export with REGULATOR role succeeds with 200 OK")
    void getComplianceExport_regulatorRole_returns200() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<String> response = regulatorTemplate.getForEntity(
                "/audit/compliance/account-access/export?accountId=ACC-1", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // =========================================================================
    // REGULATOR Least-Privilege Denials on Internal Operational Endpoints
    // =========================================================================

    @Test
    @DisplayName("GET /audit/events with REGULATOR role returns 403 Forbidden")
    void getEvents_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<ErrorResponse> response = regulatorTemplate.getForEntity(
                "/audit/events", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("GET /audit/exports with REGULATOR role returns 403 Forbidden (restricted to internal AUDITOR)")
    void getExports_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<ErrorResponse> response = regulatorTemplate.getForEntity(
                "/audit/exports?resourceId=ACC-1", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("GET /audit/verify with REGULATOR role returns 403 Forbidden")
    void getVerify_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<ErrorResponse> response = regulatorTemplate.getForEntity(
                "/audit/verify", ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("POST /audit/events with REGULATOR role returns 403 Forbidden")
    void postEvents_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        ResponseEntity<ErrorResponse> response = regulatorTemplate.postForEntity(
                "/audit/events", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("POST /audit/archive/eligible with REGULATOR role returns 403 Forbidden")
    void postArchive_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        ResponseEntity<ErrorResponse> response = regulatorTemplate.postForEntity(
                "/audit/archive/eligible", null, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("POST /audit/events/{id}/redact with REGULATOR role returns 403 Forbidden")
    void postRedact_regulatorRole_returns403() {
        TestRestTemplate regulatorTemplate = restTemplate.withBasicAuth("test-regulator", "test-regulator-password-123");
        HttpEntity<String> request = new HttpEntity<>("{\"fieldPath\":\"payload.secret\",\"reason\":\"TEST\"}", jsonHeaders());
        ResponseEntity<ErrorResponse> response = regulatorTemplate.postForEntity(
                "/audit/events/" + UUID.randomUUID() + "/redact", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("Rejected (401/403) append requests never modify database state or chain head")
    void rejectedAppends_doNotModifyDatabase() {
        // Record initial state
        Integer initialEventCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event", Integer.class);
        Long initialHeadSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String initialHeadHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);

        assertThat(initialEventCount).isEqualTo(0);
        assertThat(initialHeadSeq).isEqualTo(0L);

        // 1. Anonymous attempt
        HttpEntity<String> request = new HttpEntity<>(VALID_EVENT_JSON, jsonHeaders());
        restTemplate.postForEntity("/audit/events", request, ErrorResponse.class);

        // 2. Bad credentials attempt
        restTemplate.withBasicAuth("unknown-user", "bad-pass")
                .postForEntity("/audit/events", request, ErrorResponse.class);

        // 3. Forbidden role attempt (AUDITOR)
        restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123")
                .postForEntity("/audit/events", request, ErrorResponse.class);

        // Verify database state is strictly unmodified
        Integer currentEventCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event", Integer.class);
        Long currentHeadSeq = jdbcTemplate.queryForObject(
                "SELECT last_sequence_no FROM audit_chain_head WHERE chain_id = 1", Long.class);
        String currentHeadHash = jdbcTemplate.queryForObject(
                "SELECT last_record_hash FROM audit_chain_head WHERE chain_id = 1", String.class);

        assertThat(currentEventCount).isEqualTo(initialEventCount);
        assertThat(currentHeadSeq).isEqualTo(initialHeadSeq);
        assertThat(currentHeadHash).isEqualTo(initialHeadHash);
    }

    @Test
    @DisplayName("Idempotent append returns 201 on first call and 200 on identical replay via HTTP")
    void idempotentAppend_returns201Then200OnReplay() {
        String payload = """
                {
                    "eventType": "AUTH_LOGIN",
                    "actorId": "security-user-1",
                    "resourceType": "PORTAL",
                    "resourceId": "portal-main",
                    "payload": {"method": "CERTIFICATE"}
                }
                """;

        HttpHeaders headers = jsonHeaders();
        headers.set("Idempotency-Key", "sec-test-key-1");
        HttpEntity<String> request = new HttpEntity<>(payload, headers);

        // First call: 201 Created
        ResponseEntity<AuditEventResponse> first = restTemplate.withBasicAuth("test-writer", "test-writer-password-123")
                .postForEntity("/audit/events", request, AuditEventResponse.class);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(first.getBody()).isNotNull();
        UUID eventId = first.getBody().eventId();

        // Second call with same key: 200 OK with identical event
        ResponseEntity<AuditEventResponse> second = restTemplate.withBasicAuth("test-writer", "test-writer-password-123")
                .postForEntity("/audit/events", request, AuditEventResponse.class);

        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getBody()).isNotNull();
        assertThat(second.getBody().eventId()).isEqualTo(eventId);
        assertThat(second.getBody().recordHash()).isEqualTo(first.getBody().recordHash());

        // Event count in database must be exactly 1
        Integer currentEventCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM audit_event", Integer.class);
        assertThat(currentEventCount).isEqualTo(1);
    }

    @Test
    @DisplayName("Idempotent append with mismatched payload returns 409 Conflict via HTTP")
    void idempotentAppend_withMismatchedPayloadReturns409Conflict() {
        String payload1 = """
                {
                    "eventType": "AUTH_LOGIN",
                    "actorId": "security-user-1",
                    "resourceType": "PORTAL",
                    "resourceId": "portal-main",
                    "payload": {"method": "CERTIFICATE"}
                }
                """;

        HttpHeaders headers = jsonHeaders();
        headers.set("Idempotency-Key", "sec-test-conflict-key");
        HttpEntity<String> request1 = new HttpEntity<>(payload1, headers);

        ResponseEntity<AuditEventResponse> first = restTemplate.withBasicAuth("test-writer", "test-writer-password-123")
                .postForEntity("/audit/events", request1, AuditEventResponse.class);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        String payload2 = """
                {
                    "eventType": "AUTH_LOGIN",
                    "actorId": "security-user-1",
                    "resourceType": "PORTAL",
                    "resourceId": "portal-main",
                    "payload": {"method": "PASSWORD_COMPROMISED"}
                }
                """;
        HttpEntity<String> request2 = new HttpEntity<>(payload2, headers);

        ResponseEntity<ErrorResponse> second = restTemplate.withBasicAuth("test-writer", "test-writer-password-123")
                .postForEntity("/audit/events", request2, ErrorResponse.class);

        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(second.getBody()).isNotNull();
        assertThat(second.getBody().status()).isEqualTo(409);
        assertThat(second.getBody().message()).contains("sec-test-conflict-key");
    }

    // =========================================================================
    // Rate Limiting Servlet Registration Invariants
    // =========================================================================

    @Test
    @DisplayName("FilterRegistrationBean beans for rate limiters are explicitly disabled from servlet container auto-registration")
    void rateLimitingFilterBeans_disabledInServletContainer() {
        FilterRegistrationBean<?> ipRegistration = applicationContext.getBean(
                "preAuthIpRateLimitingFilterRegistration", FilterRegistrationBean.class);
        FilterRegistrationBean<?> principalRegistration = applicationContext.getBean(
                "postAuthPrincipalRateLimitingFilterRegistration", FilterRegistrationBean.class);

        assertThat(ipRegistration).isNotNull();
        assertThat(ipRegistration.isEnabled())
                .as("preAuthIpRateLimitingFilterRegistration must be disabled from servlet auto-registration")
                .isFalse();

        assertThat(principalRegistration).isNotNull();
        assertThat(principalRegistration.isEnabled())
                .as("postAuthPrincipalRateLimitingFilterRegistration must be disabled from servlet auto-registration")
                .isFalse();
    }
}
