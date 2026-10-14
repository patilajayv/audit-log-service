package com.example.auditlog;

import java.time.Clock;
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
}
