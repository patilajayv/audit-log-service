package com.example.auditlog.append;

/**
 * Thrown when an idempotency key is reused with a request payload that differs from the
 * originally committed audit event for that client.
 */
public class IdempotencyConflictException extends RuntimeException {

    private final String idempotencyKey;

    public IdempotencyConflictException(String idempotencyKey, String message) {
        super(message);
        this.idempotencyKey = idempotencyKey;
    }

    public String getIdempotencyKey() {
        return idempotencyKey;
    }
}
