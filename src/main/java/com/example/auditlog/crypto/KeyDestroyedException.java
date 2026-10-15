package com.example.auditlog.crypto;

/**
 * Thrown when an operation attempts to use an encryption key that has been permanently destroyed
 * (crypto-shredded) as part of a redaction or erasure workflow.
 */
public class KeyDestroyedException extends RuntimeException {

    private final String keyId;

    public KeyDestroyedException(String keyId) {
        super("Encryption key has been destroyed and is unrecoverable: " + keyId);
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }
}
