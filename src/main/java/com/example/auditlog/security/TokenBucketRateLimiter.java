package com.example.auditlog.security;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Thread-safe, bounded in-memory token-bucket rate limiter implementing strict capacity limits,
 * atomic eviction, and detached-bucket lifecycle coordination.
 *
 * <h2>Lock Hierarchy &amp; Deadlock-Free Guarantee</h2>
 * <p>All operations strictly enforce a single unidirectional lock hierarchy:
 * <pre>
 *   capacityLock (Level 1) -&gt; bucket.lock (Level 2)
 * </pre>
 * Every operation that detaches a bucket, evicts a bucket from the internal map, or inserts a new bucket
 * must acquire {@code capacityLock} before {@code bucket.lock}. Fast-path lookups for existing active
 * clients acquire only {@code bucket.lock} (Level 2) and never touch {@code capacityLock}. Circular lock
 * dependencies are impossible.
 *
 * <h2>Single-Instance Prototype Scope</h2>
 * <p><strong>Production Limitation:</strong> This rate limiter provides node-local throttling in JVM process
 * memory for single-instance prototype deployment. In a distributed, horizontally scaled multi-node deployment,
 * an external token bucket store (e.g., Redis cluster or Envoy API gateway) must be used to enforce global quotas.
 */
public class TokenBucketRateLimiter {

    private final double maxCapacity;
    private final double refillRatePerNano;
    private final int maxEntries;
    private final long idleWindowNanos;
    private final boolean enabled;

    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final ReentrantLock capacityLock = new ReentrantLock();

    /**
     * Constructs a bounded token-bucket rate limiter.
     *
     * @param requestsPerMinute sustained request quota per minute (must be &gt; 0)
     * @param burstCapacity maximum burst token capacity (must be &gt;= 1)
     * @param maxEntries maximum concurrent tracked keys before saturation enforcement
     * @param idleWindowSeconds duration after which a fully replenished bucket is deemed genuinely idle
     * @param enabled whether rate limiting is active
     */
    public TokenBucketRateLimiter(
            int requestsPerMinute,
            int burstCapacity,
            int maxEntries,
            long idleWindowSeconds,
            boolean enabled) {
        if (requestsPerMinute <= 0) {
            throw new IllegalArgumentException("requestsPerMinute must be positive: " + requestsPerMinute);
        }
        if (burstCapacity <= 0) {
            throw new IllegalArgumentException("burstCapacity must be positive: " + burstCapacity);
        }
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive: " + maxEntries);
        }
        if (idleWindowSeconds <= 0) {
            throw new IllegalArgumentException("idleWindowSeconds must be positive: " + idleWindowSeconds);
        }

        this.maxCapacity = burstCapacity;
        this.refillRatePerNano = (double) requestsPerMinute / (60.0 * 1_000_000_000.0);
        this.maxEntries = maxEntries;
        this.idleWindowNanos = idleWindowSeconds * 1_000_000_000L;
        this.enabled = enabled;
    }

    /**
     * Checks if this rate limiter is enabled.
     *
     * @return true if active, false if bypassed
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Returns the current number of tracked buckets in memory.
     *
     * @return current entry count
     */
    public int getTrackedCount() {
        return buckets.size();
    }

    /**
     * Attempts to acquire a single token for the given client key using monotonic time.
     *
     * @param clientKey the unique client identifier (e.g. client IP or authenticated principal)
     * @param nowNanos current timestamp from {@link NanoTimeSource}
     * @return {@link RateLimitStatus#ALLOWED}, {@link RateLimitStatus#QUOTA_EXHAUSTED}, or
     *         {@link RateLimitStatus#CAPACITY_SATURATED}
     */
    public RateLimitStatus tryAcquire(String clientKey, long nowNanos) {
        if (!enabled) {
            return RateLimitStatus.ALLOWED;
        }

        // 1. Fast Path: Lock-Free Map Lookup for Existing Buckets
        TokenBucket bucket = buckets.get(clientKey);
        if (bucket != null) {
            ConsumeResult res = bucket.tryConsume(nowNanos);
            if (res == ConsumeResult.ALLOWED) {
                return RateLimitStatus.ALLOWED;
            } else if (res == ConsumeResult.EXHAUSTED) {
                return RateLimitStatus.QUOTA_EXHAUSTED;
            }
            // If res == ConsumeResult.DETACHED:
            // Bucket was evicted concurrently while holding stale fast-path reference.
            // Fall through immediately to atomic resolution under capacityLock.
        }

        // 2. Atomic Fallback Path: Synchronized Capacity Reservation and Creation
        return acquireUnderCapacityLock(clientKey, nowNanos);
    }

    /**
     * Coordinates bucket lookup, safe eviction, and fresh bucket allocation under {@code capacityLock}.
     */
    private RateLimitStatus acquireUnderCapacityLock(String clientKey, long nowNanos) {
        capacityLock.lock(); // Level 1 Lock
        try {
            TokenBucket mappedBucket = buckets.get(clientKey);

            if (mappedBucket != null) {
                ConsumeResult res = mappedBucket.tryConsume(nowNanos); // Acquires Level 2 Lock internally

                if (res == ConsumeResult.ALLOWED) {
                    return RateLimitStatus.ALLOWED;
                } else if (res == ConsumeResult.EXHAUSTED) {
                    return RateLimitStatus.QUOTA_EXHAUSTED;
                } else if (res == ConsumeResult.DETACHED) {
                    // Stale detached instance detected: purge from map atomically
                    buckets.remove(clientKey, mappedBucket);
                    // Fall through to allocate a fresh bucket under this capacityLock hold
                }
            }

            // Capacity Verification and Safe Eviction under Level 1 Lock
            if (buckets.size() >= maxEntries) {
                boolean evicted = tryEvictOneIdleEntry(nowNanos);
                if (!evicted) {
                    // FAIL-CLOSED: Map is at capacity and zero entries are genuinely idle
                    return RateLimitStatus.CAPACITY_SATURATED;
                }
            }

            // Atomically allocate fresh bucket and consume exactly 1 initial token
            TokenBucket newBucket = new TokenBucket(maxCapacity, refillRatePerNano, nowNanos);
            newBucket.consumeOneInitialToken(nowNanos); // tokens = max - 1.0, lastAccessNanos = nowNanos
            buckets.put(clientKey, newBucket);

            return RateLimitStatus.ALLOWED;
        } finally {
            capacityLock.unlock(); // Release Level 1 Lock
        }
    }

    /**
     * Attempts to find and evict a single genuinely idle, fully replenished bucket.
     * Must be called while holding {@code capacityLock} (Level 1).
     */
    private boolean tryEvictOneIdleEntry(long nowNanos) {
        Iterator<Map.Entry<String, TokenBucket>> iterator = buckets.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, TokenBucket> entry = iterator.next();
            TokenBucket candidate = entry.getValue();

            // Candidate lock (Level 2) acquired inside capacityLock (Level 1)
            synchronized (candidate.lock) {
                if (candidate.isSafelyEvictable(nowNanos, idleWindowNanos)) {
                    candidate.detached = true;
                    buckets.remove(entry.getKey(), candidate);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Internal consumption outcome from a {@link TokenBucket}.
     */
    public enum ConsumeResult {
        ALLOWED,
        EXHAUSTED,
        DETACHED
    }

    /**
     * Bounded token bucket tracking token accrual and genuine client access times.
     */
    public static class TokenBucket {
        private final Object lock = new Object();
        private final double maxCapacity;
        private final double refillRatePerNano;

        private double tokens;
        private long lastRefillNanos;
        private long lastAccessNanos;
        private boolean detached = false;

        public TokenBucket(double maxCapacity, double refillRatePerNano, long initialNowNanos) {
            this.maxCapacity = maxCapacity;
            this.refillRatePerNano = refillRatePerNano;
            this.tokens = maxCapacity;
            this.lastRefillNanos = initialNowNanos;
            this.lastAccessNanos = initialNowNanos;
        }

        /**
         * Consumes exactly one initial token upon fresh bucket instantiation.
         */
        public void consumeOneInitialToken(long nowNanos) {
            synchronized (lock) {
                this.tokens = Math.max(0.0, this.maxCapacity - 1.0);
                this.lastAccessNanos = nowNanos;
                this.lastRefillNanos = nowNanos;
            }
        }

        /**
         * Attempts to consume one token using monotonic time.
         */
        public ConsumeResult tryConsume(long nowNanos) {
            synchronized (lock) {
                if (this.detached) {
                    return ConsumeResult.DETACHED;
                }
                refill(nowNanos);
                this.lastAccessNanos = nowNanos; // Update real client activity timestamp

                if (this.tokens >= 1.0) {
                    this.tokens -= 1.0;
                    return ConsumeResult.ALLOWED;
                }
                return ConsumeResult.EXHAUSTED;
            }
        }

        /**
         * Checks if this bucket is genuinely idle and fully replenished.
         * Must be called while holding {@code lock}.
         */
        public boolean isSafelyEvictable(long nowNanos, long idleWindowNanos) {
            if (this.detached) {
                return false;
            }
            refill(nowNanos);
            boolean fullyReplenished = (this.tokens >= this.maxCapacity);
            boolean genuinelyIdle = (nowNanos - this.lastAccessNanos >= idleWindowNanos);

            return fullyReplenished && genuinelyIdle;
        }

        public boolean isDetached() {
            synchronized (lock) {
                return detached;
            }
        }

        public double getTokens() {
            synchronized (lock) {
                return tokens;
            }
        }

        private void refill(long nowNanos) {
            if (nowNanos > this.lastRefillNanos) {
                long elapsed = nowNanos - this.lastRefillNanos;
                double accrued = elapsed * refillRatePerNano;
                this.tokens = Math.min(maxCapacity, this.tokens + accrued);
                this.lastRefillNanos = nowNanos;
            }
        }
    }
}
