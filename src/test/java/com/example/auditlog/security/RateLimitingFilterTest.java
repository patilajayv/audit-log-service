package com.example.auditlog.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auditlog.api.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Deterministic unit tests for {@link TokenBucketRateLimiter}, {@link PreAuthIpRateLimitingFilter},
 * and {@link PostAuthPrincipalRateLimitingFilter} using controllable monotonic time sources.
 */
class RateLimitingFilterTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private static final Instant BASE_INSTANT = Instant.parse("2026-10-15T12:00:00Z");

    private MutableNanoTimeSource nanoTimeSource;
    private MutableClock clock;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        nanoTimeSource = new MutableNanoTimeSource(1_000_000_000L); // 1 second in nanoseconds
        clock = new MutableClock(BASE_INSTANT);
    }

    @Nested
    @DisplayName("TokenBucketRateLimiter Core Algorithm & Concurrency Tests")
    class LimiterAlgorithmTests {

        @Test
        @DisplayName("Allows requests up to burst capacity then rejects when quota is exhausted")
        void allowsRequestsUpToBurstCapacityThenExhausts() {
            // 60 RPM, burst capacity of 3 tokens, max 10 entries, 300s idle window
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(60, 3, 10, 300, true);

            // First 3 requests consume the initial 3 tokens
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);

            // 4th request without advancing time is rejected
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.QUOTA_EXHAUSTED);
        }

        @Test
        @DisplayName("Refills tokens deterministically when monotonic time advances")
        void refillsTokensDeterministicallyWhenTimeAdvances() {
            // 60 RPM = 1 token per second, burst 2
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(60, 2, 10, 300, true);

            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.QUOTA_EXHAUSTED);

            // Advance monotonic time by exactly 1 second (1,000,000,000 nanos)
            nanoTimeSource.advanceSeconds(1);

            // 1 token has refilled
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            // But immediate subsequent request is exhausted again
            assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.QUOTA_EXHAUSTED);
        }

        @Test
        @DisplayName("Safely evicts fully replenished, genuinely idle buckets when capacity ceiling is reached")
        void evictsGenuinelyIdleBucketsWhenCapacityIsReached() {
            // Capacity limit = 2 entries, idle window = 10 seconds
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(60, 5, 2, 10, true);

            assertThat(limiter.tryAcquire("ip-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("ip-2", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.getTrackedCount()).isEqualTo(2);

            // Advance time past the idle window (15 seconds), allowing ip-1 and ip-2 to fully replenish and become idle
            nanoTimeSource.advanceSeconds(15);

            // Arriving client ip-3 triggers safe eviction of an idle entry
            assertThat(limiter.tryAcquire("ip-3", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.getTrackedCount()).isLessThanOrEqualTo(2);
        }

        @Test
        @DisplayName("Fails closed (CAPACITY_SATURATED) when capacity limit is reached and all entries are active")
        void failsClosedWhenCapacityIsSaturatedAndNoneAreIdle() {
            // Capacity limit = 2 entries, idle window = 60 seconds
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(60, 5, 2, 60, true);

            assertThat(limiter.tryAcquire("ip-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            assertThat(limiter.tryAcquire("ip-2", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);

            // Advance time by only 5 seconds (active window, not idle)
            nanoTimeSource.advanceSeconds(5);

            // Third client arrives: capacity is 2 and zero entries are idle -> fail-closed
            assertThat(limiter.tryAcquire("ip-3", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.CAPACITY_SATURATED);
            assertThat(limiter.getTrackedCount()).isEqualTo(2);

            // Existing clients continue to operate against their own quotas
            assertThat(limiter.tryAcquire("ip-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
        }

        @Test
        @DisplayName("Concurrent bucket creation strictly respects the configured capacity limit")
        void concurrentBucketCreationNeverExceedsCapacityLimit() throws Exception {
            final int capacity = 50;
            final int threads = 20;
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(600, 10, capacity, 300, true);

            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CountDownLatch readyLatch = new CountDownLatch(threads);
            CountDownLatch startLatch = new CountDownLatch(1);

            List<Future<RateLimitStatus>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final String key = "client-concurrent-" + i;
                futures.add(executor.submit(() -> {
                    readyLatch.countDown();
                    startLatch.await();
                    return limiter.tryAcquire(key, nanoTimeSource.nanoTime());
                }));
            }

            readyLatch.await(5, TimeUnit.SECONDS);
            startLatch.countDown();

            for (Future<RateLimitStatus> future : futures) {
                future.get(5, TimeUnit.SECONDS);
            }
            executor.shutdownNow();

            assertThat(limiter.getTrackedCount()).isLessThanOrEqualTo(capacity);
        }

        @Test
        @DisplayName("Bypasses rate limiting when enabled is false")
        void bypassesRateLimitingWhenDisabled() {
            TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(60, 1, 10, 300, false);

            for (int i = 0; i < 50; i++) {
                assertThat(limiter.tryAcquire("client-1", nanoTimeSource.nanoTime())).isEqualTo(RateLimitStatus.ALLOWED);
            }
        }
    }

    @Nested
    @DisplayName("PreAuthIpRateLimitingFilter Security & Anti-Spoofing Tests")
    class PreAuthFilterTests {

        @Test
        @DisplayName("Keys pre-auth limiter strictly by getRemoteAddr ignoring forwarded headers")
        void keysExclusivelyByRemoteAddrIgnoringForwardedHeaders() throws Exception {
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 1, 10, 300, true);
            PreAuthIpRateLimitingFilter filter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            MockHttpServletRequest request1 = new MockHttpServletRequest("POST", "/audit/events");
            request1.setRemoteAddr("192.168.1.100");
            request1.addHeader("X-Forwarded-For", "10.0.0.1, 10.0.0.2"); // Attacker trying to spoof IP

            MockHttpServletResponse response1 = new MockHttpServletResponse();
            filter.doFilter(request1, response1, new MockFilterChain());
            assertThat(response1.getStatus()).isEqualTo(200);

            // Second request from same remoteAddr with DIFFERENT forwarded header must be rate-limited
            MockHttpServletRequest request2 = new MockHttpServletRequest("POST", "/audit/events");
            request2.setRemoteAddr("192.168.1.100");
            request2.addHeader("X-Forwarded-For", "10.99.99.99");

            MockHttpServletResponse response2 = new MockHttpServletResponse();
            filter.doFilter(request2, response2, new MockFilterChain());

            assertThat(response2.getStatus()).isEqualTo(429);
            assertThat(response2.getHeader("Retry-After")).isEqualTo("60");

            ErrorResponse error = OBJECT_MAPPER.readValue(response2.getContentAsString(), ErrorResponse.class);
            assertThat(error.status()).isEqualTo(429);
            assertThat(error.message()).contains("Rate limit exceeded");
        }

        @Test
        @DisplayName("Attacker sending bogus Basic Auth does not consume victim's quota")
        void invalidAuthAttemptsThrottledByIpWithoutImpactingVictim() throws Exception {
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 1, 10, 300, true);
            PreAuthIpRateLimitingFilter filter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            // Attacker from IP 192.168.1.50 sends request with victim's username in Basic auth header
            MockHttpServletRequest attackerReq = new MockHttpServletRequest("POST", "/audit/events");
            attackerReq.setRemoteAddr("192.168.1.50");
            attackerReq.addHeader("Authorization", "Basic dmljdGltLXVzZXI6d3JvbmdwYXNzd29yZA=="); // victim-user:wrongpassword

            MockHttpServletResponse attackerRes1 = new MockHttpServletResponse();
            filter.doFilter(attackerReq, attackerRes1, new MockFilterChain());
            assertThat(attackerRes1.getStatus()).isEqualTo(200);

            // Second attempt from attacker is throttled by their own IP
            MockHttpServletResponse attackerRes2 = new MockHttpServletResponse();
            filter.doFilter(attackerReq, attackerRes2, new MockFilterChain());
            assertThat(attackerRes2.getStatus()).isEqualTo(429);

            // Real victim from IP 10.200.0.1 sends request: completely unaffected!
            MockHttpServletRequest victimReq = new MockHttpServletRequest("POST", "/audit/events");
            victimReq.setRemoteAddr("10.200.0.1");
            victimReq.addHeader("Authorization", "Basic dmljdGltLXVzZXI6Y29ycmVjdHBhc3N3b3Jk");

            MockHttpServletResponse victimRes = new MockHttpServletResponse();
            filter.doFilter(victimReq, victimRes, new MockFilterChain());
            assertThat(victimRes.getStatus()).isEqualTo(200);
        }
    }

    @Nested
    @DisplayName("PostAuthPrincipalRateLimitingFilter Behavior & Bypass Tests")
    class PostAuthFilterTests {

        @Test
        @DisplayName("Explicitly bypasses principal limiter when request is unauthenticated or anonymous")
        void explicitlyBypassesWhenUnauthenticatedOrAnonymous() throws Exception {
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 1, 10, 300, true);
            PostAuthPrincipalRateLimitingFilter filter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            // 1. Unauthenticated (null auth)
            SecurityContextHolder.clearContext();
            MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse res1 = new MockHttpServletResponse();
            MockFilterChain chain1 = new MockFilterChain();
            filter.doFilter(req1, res1, chain1);
            assertThat(res1.getStatus()).isEqualTo(200);
            assertThat(principalLimiter.getTrackedCount()).isEqualTo(0);

            // 2. Anonymous authentication token
            SecurityContextHolder.getContext().setAuthentication(
                    new AnonymousAuthenticationToken("key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
            MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse res2 = new MockHttpServletResponse();
            MockFilterChain chain2 = new MockFilterChain();
            filter.doFilter(req2, res2, chain2);
            assertThat(res2.getStatus()).isEqualTo(200);
            assertThat(principalLimiter.getTrackedCount()).isEqualTo(0);
        }

        @Test
        @DisplayName("Enforces principal quota on verified authenticated user")
        void enforcesQuotaOnVerifiedAuthenticatedUser() throws Exception {
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 2, 10, 300, true);
            PostAuthPrincipalRateLimitingFilter filter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("local_writer", "password", List.of(new SimpleGrantedAuthority("ROLE_AUDIT_WRITER"))));

            MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse res1 = new MockHttpServletResponse();
            filter.doFilter(req1, res1, new MockFilterChain());
            assertThat(res1.getStatus()).isEqualTo(200);

            MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse res2 = new MockHttpServletResponse();
            filter.doFilter(req2, res2, new MockFilterChain());
            assertThat(res2.getStatus()).isEqualTo(200);

            // 3rd request exhausts local_writer quota
            MockHttpServletRequest req3 = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse res3 = new MockHttpServletResponse();
            filter.doFilter(req3, res3, new MockFilterChain());
            assertThat(res3.getStatus()).isEqualTo(429);
            assertThat(res3.getHeader("Retry-After")).isEqualTo("60");

            // Different authenticated user local_auditor is not blocked
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("local_auditor", "password", List.of(new SimpleGrantedAuthority("ROLE_AUDITOR"))));

            MockHttpServletRequest reqAuditor = new MockHttpServletRequest("GET", "/audit/events");
            MockHttpServletResponse resAuditor = new MockHttpServletResponse();
            filter.doFilter(reqAuditor, resAuditor, new MockFilterChain());
            assertThat(resAuditor.getStatus()).isEqualTo(200);
        }
    }

    @Nested
    @DisplayName("Filter Ordering, Duplicate Execution & Registration Tests")
    class FilterOrderingAndRegistrationTests {

        @Test
        @DisplayName("SecurityConfiguration explicitly disables servlet-container auto-registration for both filters")
        void filterRegistrationBeansExplicitlyDisableServletAutoRegistration() {
            SecurityConfiguration config = new SecurityConfiguration();
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 10, 10, 300, true);
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 10, 10, 300, true);

            PreAuthIpRateLimitingFilter ipFilter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);
            PostAuthPrincipalRateLimitingFilter principalFilter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            FilterRegistrationBean<PreAuthIpRateLimitingFilter> ipRegistration =
                    config.preAuthIpRateLimitingFilterRegistration(ipFilter);
            FilterRegistrationBean<PostAuthPrincipalRateLimitingFilter> principalRegistration =
                    config.postAuthPrincipalRateLimitingFilterRegistration(principalFilter);

            assertThat(ipRegistration).isNotNull();
            assertThat(ipRegistration.isEnabled())
                    .as("PreAuthIpRateLimitingFilter must not be auto-registered in servlet container")
                    .isFalse();
            assertThat(ipRegistration.getFilter()).isSameAs(ipFilter);

            assertThat(principalRegistration).isNotNull();
            assertThat(principalRegistration.isEnabled())
                    .as("PostAuthPrincipalRateLimitingFilter must not be auto-registered in servlet container")
                    .isFalse();
            assertThat(principalRegistration.getFilter()).isSameAs(principalFilter);
        }

        @Test
        @DisplayName("Demonstrates why premature servlet-level execution bypasses post-auth rate limiting")
        void demonstratesWhyPrematureServletExecutionBypassesPostAuthLimiting() throws Exception {
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 1, 10, 300, true);
            PostAuthPrincipalRateLimitingFilter principalFilter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/events");
            MockHttpServletResponse response = new MockHttpServletResponse();

            // 1. Simulating buggy outer servlet-level execution before authentication:
            // SecurityContext is unauthenticated; filter runs OncePerRequestFilter.doFilter()
            SecurityContextHolder.clearContext();
            principalFilter.doFilter(request, response, (req, res) -> {
                // Downstream in the outer chain, request reaches Spring Security and authenticates:
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken("local_writer", "password",
                                List.of(new SimpleGrantedAuthority("ROLE_AUDIT_WRITER"))));

                // Then Spring Security executes PostAuthPrincipalRateLimitingFilter internally:
                principalFilter.doFilter(req, res, new MockFilterChain());
            });

            // Because OncePerRequestFilter set its internal attribute during outer execution,
            // the inner execution inside SecurityFilterChain was completely bypassed!
            // No tokens were consumed, leaving the principal unthrottled:
            assertThat(principalLimiter.getTrackedCount())
                    .as("Premature outer servlet execution causes inner filter to be bypassed")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Proper SecurityFilterChain ordering executes after authentication and enforces principal quota")
        void properSecurityChainOrderingEnforcesPrincipalQuota() throws Exception {
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 10, 10, 300, true);
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 2, 10, 300, true);

            PreAuthIpRateLimitingFilter ipFilter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);
            PostAuthPrincipalRateLimitingFilter principalFilter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            // Simulate the Spring Security filter chain: PreAuth -> BasicAuth -> PostAuth
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/events");
            request.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            // Step 1: Pre-auth filter consumes IP token
            ipFilter.doFilter(request, response, (req1, res1) -> {
                // Step 2: BasicAuthenticationFilter authenticates
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken("local_writer", "password",
                                List.of(new SimpleGrantedAuthority("ROLE_AUDIT_WRITER"))));

                // Step 3: Post-auth filter executes with authenticated principal
                principalFilter.doFilter(req1, res1, new MockFilterChain());
            });

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(ipLimiter.getTrackedCount()).isEqualTo(1);
            assertThat(principalLimiter.getTrackedCount()).isEqualTo(1);

            // Repeat to verify second token consumption and eventual exhaustion
            MockHttpServletRequest request2 = new MockHttpServletRequest("POST", "/audit/events");
            request2.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse response2 = new MockHttpServletResponse();

            ipFilter.doFilter(request2, response2, (req2, res2) -> {
                principalFilter.doFilter(req2, res2, new MockFilterChain());
            });
            assertThat(response2.getStatus()).isEqualTo(200);

            // 3rd request exhausts principal quota (burst = 2)
            MockHttpServletRequest request3 = new MockHttpServletRequest("POST", "/audit/events");
            request3.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse response3 = new MockHttpServletResponse();

            ipFilter.doFilter(request3, response3, (req3, res3) -> {
                principalFilter.doFilter(req3, res3, new MockFilterChain());
            });
            assertThat(response3.getStatus()).isEqualTo(429);
            assertThat(response3.getHeader("Retry-After")).isEqualTo("60");
        }

        @Test
        @DisplayName("Prevents duplicate token consumption if filter is accidentally invoked multiple times on same request")
        void preventsDuplicateTokenConsumptionOnSameRequest() throws Exception {
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 2, 10, 300, true);
            PreAuthIpRateLimitingFilter ipFilter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/events");
            request.setRemoteAddr("10.0.0.2");
            MockHttpServletResponse response = new MockHttpServletResponse();

            // First invocation in request lifecycle
            ipFilter.doFilter(request, response, (req, res) -> {
                // Simulated nested/forward dispatch in same servlet request
                ipFilter.doFilter(req, res, new MockFilterChain());
            });

            // OncePerRequestFilter should ensure the nested invocation did not consume a second token
            // Limiter has burst capacity of 2; a single subsequent new request should still succeed
            MockHttpServletRequest request2 = new MockHttpServletRequest("POST", "/audit/events");
            request2.setRemoteAddr("10.0.0.2");
            MockHttpServletResponse response2 = new MockHttpServletResponse();
            ipFilter.doFilter(request2, response2, new MockFilterChain());

            // If duplicate invocation had consumed a token, this second request would be 429
            assertThat(response2.getStatus()).isEqualTo(200);
        }

        @Test
        @DisplayName("Unauthenticated request consumes IP token but does not allocate or consume principal quota")
        void unauthenticatedRequestProtectsAuthenticationWithoutConsumingPrincipalQuota() throws Exception {
            TokenBucketRateLimiter ipLimiter = new TokenBucketRateLimiter(60, 10, 10, 300, true);
            TokenBucketRateLimiter principalLimiter = new TokenBucketRateLimiter(60, 10, 10, 300, true);

            PreAuthIpRateLimitingFilter ipFilter = new PreAuthIpRateLimitingFilter(
                    ipLimiter, nanoTimeSource, clock, OBJECT_MAPPER);
            PostAuthPrincipalRateLimitingFilter principalFilter = new PostAuthPrincipalRateLimitingFilter(
                    principalLimiter, nanoTimeSource, clock, OBJECT_MAPPER);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/events");
            request.setRemoteAddr("10.0.0.3");
            MockHttpServletResponse response = new MockHttpServletResponse();

            SecurityContextHolder.clearContext(); // Unauthenticated

            ipFilter.doFilter(request, response, (req, res) -> {
                // Basic auth fails, no principal set
                principalFilter.doFilter(req, res, new MockFilterChain());
            });

            // IP limiter tracked the IP
            assertThat(ipLimiter.getTrackedCount()).isEqualTo(1);
            // Principal limiter tracked 0 principals
            assertThat(principalLimiter.getTrackedCount()).isEqualTo(0);
        }
    }

    // -------------------------------------------------------------------------
    // Test Helpers
    // -------------------------------------------------------------------------

    private static class MutableNanoTimeSource implements NanoTimeSource {
        private final AtomicLong nanos;

        public MutableNanoTimeSource(long initialNanos) {
            this.nanos = new AtomicLong(initialNanos);
        }

        @Override
        public long nanoTime() {
            return nanos.get();
        }

        public void advanceSeconds(long seconds) {
            nanos.addAndGet(seconds * 1_000_000_000L);
        }
    }

    private static class MutableClock extends Clock {
        private Instant instant;

        public MutableClock(Instant initialInstant) {
            this.instant = initialInstant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        public void advanceSeconds(long seconds) {
            this.instant = this.instant.plusSeconds(seconds);
        }
    }
}
