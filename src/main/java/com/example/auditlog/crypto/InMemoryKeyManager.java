package com.example.auditlog.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * In-memory / software implementation of {@link KeyManager} designed strictly for prototype
 * validation and automated testing.
 *
 * <h2>Explicit Production Limitations</h2>
 *
 * <p><strong>Do not use this implementation in production.</strong> It has the following fundamental limitations:
 * <ul>
 *   <li><strong>Volatile Lifetime:</strong> Keys are stored in JVM process heap memory and are wiped on application
 *       restart or container recreation. In production, a process restart would cause unintended permanent data loss
 *       for all active encrypted data.</li>
 *   <li><strong>Process Memory Scraping:</strong> Secret keys remain in Java heap memory until garbage collected.
 *       Software key storage does not provide tamper-resistant protection against heap-dump analysis or memory scraping.</li>
 *   <li><strong>Horizontal Scaling:</strong> Keys are isolated to a single application instance and are not shared
 *       across clustered nodes.</li>
 *   <li><strong>Backup Independence:</strong> In production, cryptographic erasure requires that keys reside inside
 *       a dedicated Hardware Security Module (HSM) or managed Key Management Service (AWS KMS, HashiCorp Vault)
 *       whose lifecycle is completely isolated from database backups, snapshots, and WAL archives.</li>
 * </ul>
 */
@Component
public class InMemoryKeyManager implements KeyManager {

    private static final Logger log = LoggerFactory.getLogger(InMemoryKeyManager.class);
    private static final String AES_ALGORITHM = "AES";
    private static final int KEY_SIZE_BITS = 256;

    private final ConcurrentHashMap<String, SecretKey> activeKeys = new ConcurrentHashMap<>();
    private final Set<String> destroyedKeys = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public SecretKey generateKey(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            throw new IllegalArgumentException("keyId must not be blank");
        }
        if (destroyedKeys.contains(keyId)) {
            throw new IllegalStateException("Cannot generate key with ID of previously destroyed key: " + keyId);
        }
        if (activeKeys.containsKey(keyId)) {
            throw new IllegalStateException("Key already exists with ID: " + keyId);
        }

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(KEY_SIZE_BITS, secureRandom);
            SecretKey secretKey = keyGen.generateKey();
            activeKeys.put(keyId, secretKey);
            log.debug("Generated new 256-bit AES DEK: keyId={}", keyId);
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES algorithm unavailable in runtime environment", e);
        }
    }

    @Override
    public Optional<SecretKey> getKey(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            return Optional.empty();
        }
        if (destroyedKeys.contains(keyId)) {
            throw new KeyDestroyedException(keyId);
        }
        return Optional.ofNullable(activeKeys.get(keyId));
    }

    @Override
    public boolean destroyKey(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            return false;
        }
        SecretKey removed = activeKeys.remove(keyId);
        boolean newlyDestroyed = destroyedKeys.add(keyId);
        if (removed != null || newlyDestroyed) {
            log.info("Crypto-shredded encryption key: keyId={}", keyId);
            return true;
        }
        return false;
    }

    @Override
    public boolean isKeyActive(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            return false;
        }
        return activeKeys.containsKey(keyId) && !destroyedKeys.contains(keyId);
    }

    @Override
    public boolean isKeyDestroyed(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            return false;
        }
        return destroyedKeys.contains(keyId);
    }

    /**
     * Resets all keys in this manager. Intended strictly for test fixture teardown.
     */
    public void reset() {
        activeKeys.clear();
        destroyedKeys.clear();
    }
}
