package com.example.auditlog.security;

import com.example.auditlog.archival.AuditRetentionProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.Set;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

/**
 * Spring Security configuration enforcing stateless HTTP Basic authentication,
 * BCrypt password hashing, and role-based authorization for the audit-log-service.
 *
 * <p>Access rules:
 * <ul>
 *   <li>{@code POST /audit/events} requires role {@code AUDIT_WRITER}</li>
 *   <li>{@code GET /audit/events} requires role {@code AUDITOR}</li>
 *   <li>{@code GET /audit/verify} requires role {@code AUDITOR}</li>
 *   <li>{@code POST /audit/archive/**} requires role {@code AUDIT_WRITER}</li>
 *   <li>All other requests are denied by default</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({
        SecurityUserProperties.class,
        AuditRetentionProperties.class,
        com.example.auditlog.export.AuditExportProperties.class,
        RateLimitingProperties.class
})
public class SecurityConfiguration {

    private static final Set<String> INSECURE_PASSWORDS = Set.of(
            "password", "changeme", "admin", "secret", "writer-secret", "auditor-secret",
            "regulator-secret", "local-writer-secret-password", "local-auditor-secret-password",
            "local-regulator-secret-password"
    );

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            RestAuthenticationEntryPoint authenticationEntryPoint,
            RestAccessDeniedHandler accessDeniedHandler,
            PreAuthIpRateLimitingFilter preAuthIpRateLimitingFilter,
            PostAuthPrincipalRateLimitingFilter postAuthPrincipalRateLimitingFilter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(basic -> basic.authenticationEntryPoint(authenticationEntryPoint))
                .addFilterBefore(preAuthIpRateLimitingFilter, org.springframework.security.web.authentication.www.BasicAuthenticationFilter.class)
                .addFilterAfter(postAuthPrincipalRateLimitingFilter, org.springframework.security.web.authentication.www.BasicAuthenticationFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/audit/events").hasRole("AUDIT_WRITER")
                        .requestMatchers(HttpMethod.POST, "/audit/events/*/redact").hasRole("AUDIT_WRITER")
                        .requestMatchers(HttpMethod.POST, "/audit/archive/**").hasRole("AUDIT_WRITER")
                        .requestMatchers(HttpMethod.GET, "/audit/compliance/account-access").hasAnyRole("REGULATOR", "AUDITOR")
                        .requestMatchers(HttpMethod.GET, "/audit/compliance/account-access/export").hasAnyRole("REGULATOR", "AUDITOR")
                        .requestMatchers(HttpMethod.GET, "/audit/events").hasRole("AUDITOR")
                        .requestMatchers(HttpMethod.GET, "/audit/verify").hasRole("AUDITOR")
                        .requestMatchers(HttpMethod.GET, "/audit/exports").hasRole("AUDITOR")
                        .anyRequest().denyAll()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(
            SecurityUserProperties properties,
            PasswordEncoder passwordEncoder,
            Environment environment) {
        boolean isLocalOrTest = environment.acceptsProfiles(Profiles.of("local", "test"));

        String writerUser = properties.getWriter() != null ? properties.getWriter().getUsername() : null;
        String writerPass = properties.getWriter() != null ? properties.getWriter().getPassword() : null;
        String auditorUser = properties.getAuditor() != null ? properties.getAuditor().getUsername() : null;
        String auditorPass = properties.getAuditor() != null ? properties.getAuditor().getPassword() : null;
        String regulatorUser = properties.getRegulator() != null ? properties.getRegulator().getUsername() : null;
        String regulatorPass = properties.getRegulator() != null ? properties.getRegulator().getPassword() : null;

        if (isLocalOrTest) {
            if (!StringUtils.hasText(writerUser)) {
                writerUser = "test-writer";
            }
            if (!StringUtils.hasText(writerPass)) {
                writerPass = "test-writer-password-123";
            }
            if (!StringUtils.hasText(auditorUser)) {
                auditorUser = "test-auditor";
            }
            if (!StringUtils.hasText(auditorPass)) {
                auditorPass = "test-auditor-password-123";
            }
            if (!StringUtils.hasText(regulatorUser)) {
                regulatorUser = "test-regulator";
            }
            if (!StringUtils.hasText(regulatorPass)) {
                regulatorPass = "test-regulator-password-123";
            }
        } else {
            validateProductionCredentials("writer", writerUser, writerPass);
            validateProductionCredentials("auditor", auditorUser, auditorPass);
            validateProductionCredentials("regulator", regulatorUser, regulatorPass);
        }

        UserDetails writer = User.withUsername(writerUser)
                .password(passwordEncoder.encode(writerPass))
                .roles("AUDIT_WRITER")
                .build();

        UserDetails auditor = User.withUsername(auditorUser)
                .password(passwordEncoder.encode(auditorPass))
                .roles("AUDITOR")
                .build();

        UserDetails regulator = User.withUsername(regulatorUser)
                .password(passwordEncoder.encode(regulatorPass))
                .roles("REGULATOR")
                .build();

        return new InMemoryUserDetailsManager(writer, auditor, regulator);
    }

    private void validateProductionCredentials(String roleName, String username, String password) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalStateException("Production startup failed: " + roleName + " username is required.");
        }
        if (!StringUtils.hasText(password)) {
            throw new IllegalStateException("Production startup failed: " + roleName + " password is required.");
        }
        if (password.length() < 8) {
            throw new IllegalStateException("Production startup failed: " + roleName + " password must be at least 8 characters.");
        }
        if (INSECURE_PASSWORDS.contains(password.toLowerCase())) {
            throw new IllegalStateException("Production startup failed: " + roleName + " password is an insecure default placeholder.");
        }
    }

    @Bean
    public RestAuthenticationEntryPoint restAuthenticationEntryPoint(ObjectMapper objectMapper, Clock clock) {
        return new RestAuthenticationEntryPoint(objectMapper, clock);
    }

    @Bean
    public RestAccessDeniedHandler restAccessDeniedHandler(ObjectMapper objectMapper, Clock clock) {
        return new RestAccessDeniedHandler(objectMapper, clock);
    }

    @Bean
    public NanoTimeSource nanoTimeSource() {
        return NanoTimeSource.system();
    }

    @Bean
    public TokenBucketRateLimiter ipRateLimiter(RateLimitingProperties properties) {
        return new TokenBucketRateLimiter(
                properties.getIpRequestsPerMinute(),
                properties.getIpBurstCapacity(),
                properties.getIpMaxBuckets(),
                properties.getIdleWindowSeconds(),
                properties.isEnabled());
    }

    @Bean
    public TokenBucketRateLimiter principalRateLimiter(RateLimitingProperties properties) {
        return new TokenBucketRateLimiter(
                properties.getPrincipalRequestsPerMinute(),
                properties.getPrincipalBurstCapacity(),
                properties.getPrincipalMaxBuckets(),
                properties.getIdleWindowSeconds(),
                properties.isEnabled());
    }

    @Bean
    public PreAuthIpRateLimitingFilter preAuthIpRateLimitingFilter(
            TokenBucketRateLimiter ipRateLimiter,
            NanoTimeSource nanoTimeSource,
            Clock clock,
            ObjectMapper objectMapper) {
        return new PreAuthIpRateLimitingFilter(ipRateLimiter, nanoTimeSource, clock, objectMapper);
    }

    @Bean
    public FilterRegistrationBean<PreAuthIpRateLimitingFilter> preAuthIpRateLimitingFilterRegistration(
            PreAuthIpRateLimitingFilter filter) {
        FilterRegistrationBean<PreAuthIpRateLimitingFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public PostAuthPrincipalRateLimitingFilter postAuthPrincipalRateLimitingFilter(
            TokenBucketRateLimiter principalRateLimiter,
            NanoTimeSource nanoTimeSource,
            Clock clock,
            ObjectMapper objectMapper) {
        return new PostAuthPrincipalRateLimitingFilter(principalRateLimiter, nanoTimeSource, clock, objectMapper);
    }

    @Bean
    public FilterRegistrationBean<PostAuthPrincipalRateLimitingFilter> postAuthPrincipalRateLimitingFilterRegistration(
            PostAuthPrincipalRateLimitingFilter filter) {
        FilterRegistrationBean<PostAuthPrincipalRateLimitingFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
