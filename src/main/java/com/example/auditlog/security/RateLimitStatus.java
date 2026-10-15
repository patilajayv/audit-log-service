package com.example.auditlog.security;

/**
 * Outcome of an attempted token acquisition against {@link TokenBucketRateLimiter}.
 */
public enum RateLimitStatus {

    /** Request permitted within configured token quota. */
    ALLOWED,

    /** Client exceeded allotted request quota (tokens exhausted). */
    QUOTA_EXHAUSTED,

    /** Rate limiter capacity ceiling reached and zero entries are safely evictable. */
    CAPACITY_SATURATED
}
