package com.example.auditlog.api;

import java.time.Instant;

/**
 * Standard sanitized error response returned for client validation errors,
 * protocol violations, and internal server errors.
 *
 * <p>Never includes stack traces, SQL syntax, database constraint names, or sensitive internal details.
 */
public record ErrorResponse(
        int status,
        String error,
        String message,
        Instant timestamp) {}
