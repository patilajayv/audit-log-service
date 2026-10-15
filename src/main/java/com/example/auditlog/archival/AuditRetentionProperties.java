package com.example.auditlog.archival;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for the audit event retention window.
 *
 * <p>Bound from {@code audit.retention.window-days} (environment variable
 * {@code AUDIT_RETENTION_WINDOW_DAYS}). No production default is provided;
 * the archival service validates that the configured value is a positive integer
 * at invocation time.
 */
@ConfigurationProperties(prefix = "audit.retention")
public class AuditRetentionProperties {

    private Integer windowDays;

    public Integer getWindowDays() {
        return windowDays;
    }

    public void setWindowDays(Integer windowDays) {
        this.windowDays = windowDays;
    }
}
