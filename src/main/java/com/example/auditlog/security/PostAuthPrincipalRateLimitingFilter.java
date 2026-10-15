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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Post-authentication rate-limiting filter enforcing quotas per verified authenticated principal.
 *
 * <p><strong>Security Invariants:</strong>
 * <ul>
 *   <li>Explicitly bypasses unauthenticated, anonymous, or missing credentials so as not to interfere
 *       with downstream authorization challenges or authentication entry point handlers.</li>
 *   <li>Applies rate limits strictly to verified principals ({@code auth.getName()}) extracted from
 *       {@link SecurityContextHolder} after successful credential verification.</li>
 * </ul>
 */
public class PostAuthPrincipalRateLimitingFilter extends OncePerRequestFilter {

    private final TokenBucketRateLimiter principalLimiter;
    private final NanoTimeSource nanoTimeSource;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    public PostAuthPrincipalRateLimitingFilter(
            TokenBucketRateLimiter principalLimiter,
            NanoTimeSource nanoTimeSource,
            Clock clock,
            ObjectMapper objectMapper) {
        this.principalLimiter = principalLimiter;
        this.nanoTimeSource = nanoTimeSource;
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!principalLimiter.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // 1. Explicitly bypass when authentication is missing, unauthenticated, or anonymous
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        String principalName = auth.getName();
        if (!StringUtils.hasText(principalName)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Apply authenticated principal quota
        long nowNanos = nanoTimeSource.nanoTime();
        RateLimitStatus status = principalLimiter.tryAcquire("user:" + principalName, nowNanos);

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
