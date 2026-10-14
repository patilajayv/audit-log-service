package com.example.auditlog.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for HTTP Basic authentication credentials.
 *
 * <p>Separates roles into writer and auditor accounts. Production deployments must supply
 * non-default credentials through environment variables or vault references.
 */
@ConfigurationProperties(prefix = "audit.security")
public class SecurityUserProperties {

    private UserCredentials writer = new UserCredentials();
    private UserCredentials auditor = new UserCredentials();

    public UserCredentials getWriter() {
        return writer;
    }

    public void setWriter(UserCredentials writer) {
        this.writer = writer;
    }

    public UserCredentials getAuditor() {
        return auditor;
    }

    public void setAuditor(UserCredentials auditor) {
        this.auditor = auditor;
    }

    public static class UserCredentials {
        private String username;
        private String password;

        public UserCredentials() {}

        public UserCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
