package com.example.auditlog.security;

import com.example.auditlog.api.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Pre-authentication rate-limiting filter enforcing IP-level abuse prevention before credentials
 * reach {@link org.springframework.security.web.authentication.www.BasicAuthenticationFilter}.
 *
 * <p><strong>Anti-Spoofing &amp; DoS Mitigation:</strong>
 * <ul>
 *   <li>Keyed strictly by {@link HttpServletRequest#getRemoteAddr()}. Forwarded headers (e.g.
 *       {@code X-Forwarded-For}) and unauthenticated usernames are never inspected or trusted.</li>
 *   <li>Mitigates BCrypt password-hashing denial of service by throttling brute-force or flooding
 *       attempts before CPU-intensive cryptographic verification.</li>
 * </ul>
 */
public class PreAuthIpRateLimitingFilter extends OncePerRequestFilter {

    private final TokenBucketRateLimiter ipLimiter;
    private final NanoTimeSource nanoTimeSource;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    public PreAuthIpRateLimitingFilter(
            TokenBucketRateLimiter ipLimiter,
            NanoTimeSource nanoTimeSource,
            Clock clock,
            ObjectMapper objectMapper) {
        this.ipLimiter = ipLimiter;
        this.nanoTimeSource = nanoTimeSource;
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!ipLimiter.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Strictly key by remote address; never trust forwarded headers
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = (clientIp != null && !clientIp.isBlank()) ? "ip:" + clientIp : "ip:unknown";

        long nowNanos = nanoTimeSource.nanoTime();
        RateLimitStatus status = ipLimiter.tryAcquire(rateLimitKey, nowNanos);

        if (status == RateLimitStatus.ALLOWED) {
            filterChain.doFilter(request, response);
            return;
        }

        sendRateLimitResponse(response, status);
    }

    private void sendRateLimitResponse(HttpServletResponse response, RateLimitStatus status) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Retry-After", "60");

        String message = (status == RateLimitStatus.CAPACITY_SATURATED)
                ? "Rate limiter capacity saturated under heavy load. Please retry after some time."
                : "Rate limit exceeded. Please retry after some time.";

        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase(),
                message,
                clock.instant());

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
