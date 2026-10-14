package com.example.auditlog.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.AuditLogConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Unit and context runner tests for external credential sourcing and production startup validation.
 */
class SecurityCredentialValidationTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    JacksonAutoConfiguration.class
            ))
            .withUserConfiguration(
                    AuditLogConfiguration.class,
                    SecurityConfiguration.class
            );

    @Test
    @DisplayName("Fails startup in production mode when writer username is missing")
    void failsStartupWhenWriterUsernameMissing() {
        contextRunner
                .withPropertyValues(
                        "audit.security.writer.password=prod-writer-strong-pass",
                        "audit.security.auditor.username=prod-auditor",
                        "audit.security.auditor.password=prod-auditor-strong-pass"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("Production startup failed: writer username is required");
                });
    }

    @Test
    @DisplayName("Fails startup in production mode when writer password is missing")
    void failsStartupWhenWriterPasswordMissing() {
        contextRunner
                .withPropertyValues(
                        "audit.security.writer.username=prod-writer",
                        "audit.security.auditor.username=prod-auditor",
                        "audit.security.auditor.password=prod-auditor-strong-pass"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("Production startup failed: writer password is required");
                });
    }

    @Test
    @DisplayName("Fails startup in production mode when password is shorter than 8 characters")
    void failsStartupWhenPasswordTooShort() {
        contextRunner
                .withPropertyValues(
                        "audit.security.writer.username=prod-writer",
                        "audit.security.writer.password=short",
                        "audit.security.auditor.username=prod-auditor",
                        "audit.security.auditor.password=prod-auditor-strong-pass"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("must be at least 8 characters");
                });
    }

    @Test
    @DisplayName("Fails startup in production mode when password is an insecure placeholder")
    void failsStartupWhenPasswordIsInsecurePlaceholder() {
        contextRunner
                .withPropertyValues(
                        "audit.security.writer.username=prod-writer",
                        "audit.security.writer.password=writer-secret",
                        "audit.security.auditor.username=prod-auditor",
                        "audit.security.auditor.password=prod-auditor-strong-pass"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("is an insecure default placeholder");
                });
    }

    @Test
    @DisplayName("Succeeds startup in production mode with strong dedicated credentials")
    void succeedsStartupInProductionWithValidCredentials() {
        contextRunner
                .withPropertyValues(
                        "audit.security.writer.username=prod-writer",
                        "audit.security.writer.password=prod-writer-strong-password-2026",
                        "audit.security.auditor.username=prod-auditor",
                        "audit.security.auditor.password=prod-auditor-strong-password-2026"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityConfiguration.class);
                });
    }

    @Test
    @DisplayName("Succeeds startup in test profile with safe test defaults")
    void succeedsStartupInTestProfile() {
        contextRunner
                .withPropertyValues("spring.profiles.active=test")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityConfiguration.class);
                });
    }

    @Test
    @DisplayName("Succeeds startup in local profile with safe local defaults")
    void succeedsStartupInLocalProfile() {
        contextRunner
                .withPropertyValues("spring.profiles.active=local")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityConfiguration.class);
                });
    }
}
