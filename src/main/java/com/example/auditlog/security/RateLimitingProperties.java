package com.example.auditlog.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for two-tier rate limiting.
 */
@ConfigurationProperties(prefix = "audit.rate-limit")
public class RateLimitingProperties {

    /** Master toggle for rate limiting. */
    private boolean enabled = true;

    /** Sustained requests per minute per IP address. */
    private int ipRequestsPerMinute = 120;

    /** Maximum burst token capacity per IP address. */
    private int ipBurstCapacity = 30;

    /** Maximum tracked IP buckets in memory before capacity saturation. */
    private int ipMaxBuckets = 5000;

    /** Sustained requests per minute per authenticated principal. */
    private int principalRequestsPerMinute = 240;

    /** Maximum burst token capacity per authenticated principal. */
    private int principalBurstCapacity = 60;

    /** Maximum tracked principal buckets in memory before capacity saturation. */
    private int principalMaxBuckets = 1000;

    /** Idle duration in seconds after which fully replenished buckets may be safely evicted. */
    private long idleWindowSeconds = 300;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getIpRequestsPerMinute() {
        return ipRequestsPerMinute;
    }

    public void setIpRequestsPerMinute(int ipRequestsPerMinute) {
        this.ipRequestsPerMinute = ipRequestsPerMinute;
    }

    public int getIpBurstCapacity() {
        return ipBurstCapacity;
    }

    public void setIpBurstCapacity(int ipBurstCapacity) {
        this.ipBurstCapacity = ipBurstCapacity;
    }

    public int getIpMaxBuckets() {
        return ipMaxBuckets;
    }

    public void setIpMaxBuckets(int ipMaxBuckets) {
        this.ipMaxBuckets = ipMaxBuckets;
    }

    public int getPrincipalRequestsPerMinute() {
        return principalRequestsPerMinute;
    }

    public void setPrincipalRequestsPerMinute(int principalRequestsPerMinute) {
        this.principalRequestsPerMinute = principalRequestsPerMinute;
    }

    public int getPrincipalBurstCapacity() {
        return principalBurstCapacity;
    }

    public void setPrincipalBurstCapacity(int principalBurstCapacity) {
        this.principalBurstCapacity = principalBurstCapacity;
    }

    public int getPrincipalMaxBuckets() {
        return principalMaxBuckets;
    }

    public void setPrincipalMaxBuckets(int principalMaxBuckets) {
        this.principalMaxBuckets = principalMaxBuckets;
    }

    public long getIdleWindowSeconds() {
        return idleWindowSeconds;
    }

    public void setIdleWindowSeconds(long idleWindowSeconds) {
        this.idleWindowSeconds = idleWindowSeconds;
    }
}
