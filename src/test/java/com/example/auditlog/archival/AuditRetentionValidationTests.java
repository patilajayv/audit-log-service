package com.example.auditlog.archival;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Unit tests validating externalized retention window configuration and fail-fast startup behavior.
 */
class AuditRetentionValidationTests {

    @Test
    @DisplayName("Fails startup in production mode when audit.retention.window-days is missing")
    void testProductionStartupFailsWhenWindowDaysMissing() {
        MockEnvironment env = new MockEnvironment(); // default profile (production)
        AuditRetentionProperties props = new AuditRetentionProperties();
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        assertThatThrownBy(service::validateRetentionConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("audit.retention.window-days is required outside local/test profiles");
    }

    @Test
    @DisplayName("Fails startup in production mode when audit.retention.window-days is zero or negative")
    void testProductionStartupFailsWhenWindowDaysZeroOrNegative() {
        MockEnvironment env = new MockEnvironment();
        AuditRetentionProperties props = new AuditRetentionProperties();
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        props.setWindowDays(0);
        assertThatThrownBy(service::validateRetentionConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be a positive integer");

        props.setWindowDays(-10);
        assertThatThrownBy(service::validateRetentionConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be a positive integer");
    }

    @Test
    @DisplayName("Succeeds startup in production mode with valid positive retention window")
    void testProductionStartupSucceedsWithPositiveWindow() {
        MockEnvironment env = new MockEnvironment();
        AuditRetentionProperties props = new AuditRetentionProperties();
        props.setWindowDays(90);
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        assertThatCode(service::validateRetentionConfiguration).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Succeeds startup in test profile with safe test defaults")
    void testTestProfileStartupSucceeds() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        AuditRetentionProperties props = new AuditRetentionProperties();
        props.setWindowDays(30);
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        assertThatCode(service::validateRetentionConfiguration).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Succeeds startup in local profile with safe local defaults")
    void testLocalProfileStartupSucceeds() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("local");
        AuditRetentionProperties props = new AuditRetentionProperties();
        props.setWindowDays(90);
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        assertThatCode(service::validateRetentionConfiguration).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Fails startup in local profile if windowDays is explicitly negative")
    void testLocalProfileStartupFailsIfNegative() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("local");
        AuditRetentionProperties props = new AuditRetentionProperties();
        props.setWindowDays(-1);
        AuditArchivalService service = new AuditArchivalService(null, props, Clock.systemUTC(), env);

        assertThatThrownBy(service::validateRetentionConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be a positive integer if provided");
    }
}
