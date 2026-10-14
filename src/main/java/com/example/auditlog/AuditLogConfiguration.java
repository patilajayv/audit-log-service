package com.example.auditlog;

import java.time.Clock;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Application-level bean configuration.
 *
 * <p>A {@link Clock} bean is defined here so that application services can receive it via
 * constructor injection, which makes time-dependent behaviour testable by substituting a
 * fixed-time clock in tests without additional mocking frameworks.
 */
@Configuration
public class AuditLogConfiguration {

    /**
     * Returns a UTC system clock for production use.
     *
     * <p>Tests can override this bean with {@code Clock.fixed(...)} to produce deterministic
     * timestamps.
     */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Configures Jackson to enforce strict duplicate-key detection on all JSON parsing
     * (both at the root request level and in nested payload objects), adhering strictly to
     * RFC 8785 §3.2.3 and I-JSON (RFC 7493 §2.3).
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer jsonCustomizer() {
        return builder -> builder.featuresToEnable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    /**
     * Registers the {@link RequestBodySizeLimitFilter} to enforce a strict request-body size limit
     * (default 1 MiB) before any request body is deserialized or processed.
     */
    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<com.example.auditlog.api.RequestBodySizeLimitFilter> requestBodySizeLimitFilter(
            @org.springframework.beans.factory.annotation.Value("${audit.api.max-request-size-bytes:1048576}") long maxBodyBytes) {
        org.springframework.boot.web.servlet.FilterRegistrationBean<com.example.auditlog.api.RequestBodySizeLimitFilter> registration =
                new org.springframework.boot.web.servlet.FilterRegistrationBean<>();
        registration.setFilter(new com.example.auditlog.api.RequestBodySizeLimitFilter(maxBodyBytes));
        registration.addUrlPatterns("/audit/events/*", "/audit/events");
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
