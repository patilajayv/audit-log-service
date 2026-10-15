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
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
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
    // Database Invariant Verification
    // =========================================================================

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
}
