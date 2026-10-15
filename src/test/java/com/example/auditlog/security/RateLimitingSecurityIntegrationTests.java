package com.example.auditlog.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.api.ErrorResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Isolated end-to-end integration test validating authenticated-principal rate limiting
 * through the live Spring Boot HTTP stack.
 *
 * <p>Uses an isolated rate-limit configuration (burst=3, sustained=1 RPM) and an elevated IP burst
 * ceiling (100) so that principal quota exhaustion is verified cleanly over live HTTP without
 * IP-level interference, time-refill drift, or cross-test state pollution.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "audit.rate-limit.enabled=true",
                "audit.rate-limit.ip-burst-capacity=100",
                "audit.rate-limit.ip-requests-per-minute=120",
                "audit.rate-limit.principal-burst-capacity=3",
                "audit.rate-limit.principal-requests-per-minute=1",
                "audit.rate-limit.idle-window-seconds=300"
        }
)
class RateLimitingSecurityIntegrationTests {

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

    @Test
    @DisplayName("Authenticated principal rate limiting enforces quota through live HTTP stack")
    void authenticatedPrincipal_throttledAfterBurstAllowance() {
        TestRestTemplate auditorTemplate = restTemplate.withBasicAuth("test-auditor", "test-auditor-password-123");

        // 1. First 3 requests succeed within principal burst allowance (burst = 3)
        for (int i = 0; i < 3; i++) {
            ResponseEntity<String> response = auditorTemplate.getForEntity("/audit/verify", String.class);
            assertThat(response.getStatusCode())
                    .as("Request %d should succeed within burst allowance", i + 1)
                    .isEqualTo(HttpStatus.OK);
        }

        // 2. 4th request exhausts principal quota and receives HTTP 429 Too Many Requests
        ResponseEntity<ErrorResponse> throttled = auditorTemplate.getForEntity("/audit/verify", ErrorResponse.class);
        assertThat(throttled.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(throttled.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("60");
        assertThat(throttled.getBody()).isNotNull();
        assertThat(throttled.getBody().status()).isEqualTo(429);
        assertThat(throttled.getBody().error()).isEqualTo("Too Many Requests");
        assertThat(throttled.getBody().message()).isEqualTo("Rate limit exceeded. Please retry after some time.");

        // 3. A different authenticated principal (test-writer) is NOT throttled by test-auditor's quota
        TestRestTemplate writerTemplate = restTemplate.withBasicAuth("test-writer", "test-writer-password-123");
        ResponseEntity<ErrorResponse> writerResponse = writerTemplate.getForEntity("/audit/verify", ErrorResponse.class);
        // test-writer is rejected by RBAC authorization (403 Forbidden), proving it reached authorization and was NOT rate-limited (429)
        assertThat(writerResponse.getStatusCode())
                .as("Different authenticated principal must not be blocked by another's exhausted quota")
                .isEqualTo(HttpStatus.FORBIDDEN);
    }
}
