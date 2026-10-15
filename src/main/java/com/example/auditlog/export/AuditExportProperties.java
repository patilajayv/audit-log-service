package com.example.auditlog.export;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for bounding bulk export payload sizes and memory consumption.
 *
 * <p>Protects the service against memory exhaustion and denial-of-service:
 * <ul>
 *   <li>{@code maxMatchedEvents}: maximum allowed matching events returned in a single bundle (default: 1,000).</li>
 *   <li>{@code maxTotalRecords}: maximum allowed total chain length (events + witnesses) from genesis to head (default: 10,000).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "audit.export")
public class AuditExportProperties {

    private int maxMatchedEvents = 1000;
    private int maxTotalRecords = 10000;

    public int getMaxMatchedEvents() {
        return maxMatchedEvents;
    }

    public void setMaxMatchedEvents(int maxMatchedEvents) {
        if (maxMatchedEvents <= 0) {
            throw new IllegalArgumentException("maxMatchedEvents must be positive");
        }
        this.maxMatchedEvents = maxMatchedEvents;
    }

    public int getMaxTotalRecords() {
        return maxTotalRecords;
    }

    public void setMaxTotalRecords(int maxTotalRecords) {
        if (maxTotalRecords <= 0) {
            throw new IllegalArgumentException("maxTotalRecords must be positive");
        }
        this.maxTotalRecords = maxTotalRecords;
    }
}
