package com.example.auditlog.api;

import java.io.IOException;

/**
 * Thrown when an incoming HTTP request body or export bundle exceeds configured size limits.
 */
public class PayloadTooLargeException extends RuntimeException {

    public PayloadTooLargeException(String message) {
        super(message);
    }

    public PayloadTooLargeException(String message, Throwable cause) {
        super(message, cause);
    }
}
