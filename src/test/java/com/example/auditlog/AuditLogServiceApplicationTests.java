package com.example.auditlog;

import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Smoke test that verifies the Spring application context loads successfully
 * without a running database.
 *
 * <p>The DataSource and JdbcTemplate auto-configurations are excluded because no
 * database is available in this test environment. {@code JdbcTemplate} and {@code Clock}
 * are provided as mocks so that application-layer beans (e.g. {@link com.example.auditlog.append.AuditAppendService})
 * can be wired without a live DataSource.
 */
@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration"
})
class AuditLogServiceApplicationTests {

    @MockBean
    JdbcTemplate jdbcTemplate;

    @Test
    void contextLoads() {
    }
}
