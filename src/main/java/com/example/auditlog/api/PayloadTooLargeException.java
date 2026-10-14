package com.example.auditlog.api;

import java.io.IOException;

/**
 * Thrown when an incoming HTTP request body exceeds the configured size limit.
 */
public class PayloadTooLargeException extends IOException {

    public PayloadTooLargeException(String message) {
        super(message);
    }
}
