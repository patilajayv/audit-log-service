package com.example.auditlog.redaction;

/**
 * Thrown when an error occurs while attempting to destroy an encryption key in the Key Management Service.
 */
public class RedactionKeyDestructionException extends RuntimeException {

    private final String keyId;

    public RedactionKeyDestructionException(String keyId, Throwable cause) {
        super("Key destruction failed in Key Management Service for keyId: " + keyId, cause);
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }
}
