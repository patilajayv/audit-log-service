package com.example.auditlog.crypto;

import java.util.Optional;
import javax.crypto.SecretKey;

/**
 * Interface abstracting Data Encryption Key (DEK) lifecycle management.
 *
 * <p>Supports generation, retrieval, and permanent destruction (crypto-shredding) of symmetric keys.
 * In production environments, implementations are backed by an external Key Management Service
 * (e.g. AWS KMS, HashiCorp Vault) whose master keys reside in Hardware Security Modules (HSMs)
 * completely isolated from the database and application backup lifecycle.
 */
public interface KeyManager {

    /**
     * Generates and registers a new 256-bit AES Data Encryption Key.
     *
     * @param keyId unique identifier for the key
     * @return the generated SecretKey
     * @throws IllegalArgumentException if keyId is blank
     * @throws IllegalStateException    if a key with the given ID already exists
     */
    SecretKey generateKey(String keyId);

    /**
     * Retrieves an active DEK for decryption.
     *
     * @param keyId identifier of the key
     * @return Optional containing the active SecretKey, or empty if the key does not exist
     * @throws KeyDestroyedException if the key existed but was permanently destroyed
     */
    Optional<SecretKey> getKey(String keyId);

    /**
     * Permanently destroys the specified DEK.
     *
     * <p>This method is idempotent: destroying an already-destroyed or non-existent key returns
     * cleanly without throwing an exception.
     *
     * @param keyId identifier of the key to destroy
     * @return true if the key was active and newly destroyed; false if already destroyed or absent
     */
    boolean destroyKey(String keyId);

    /**
     * Checks whether a key currently exists and is active (not destroyed).
     *
     * @param keyId identifier of the key
     * @return true if the key is active, false otherwise
     */
    boolean isKeyActive(String keyId);

    /**
     * Checks whether a key was explicitly destroyed.
     *
     * @param keyId identifier of the key
     * @return true if the key was destroyed, false otherwise
     */
    boolean isKeyDestroyed(String keyId);
}
