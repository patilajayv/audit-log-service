package com.example.auditlog.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Service providing AES-256-GCM encryption and decryption for sensitive payload fields.
 *
 * <p>Uses 96-bit (12-byte) initialization vectors (IVs) and 128-bit authentication tags,
 * ensuring both confidentiality and cryptographic integrity. Keys are sourced from {@link KeyManager}.
 */
@Service
public class AuditCryptoService {

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12;

    private final KeyManager keyManager;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuditCryptoService(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * Encrypts plaintext under the specified key using AES-256-GCM and returns an {@link EncryptedEnvelope}.
     *
     * @param keyId     the identifier of the DEK
     * @param plaintext the raw string value to encrypt
     * @return the encrypted envelope
     * @throws IllegalArgumentException if keyId is blank or plaintext is null
     * @throws KeyDestroyedException    if the key was permanently destroyed
     */
    public EncryptedEnvelope encrypt(String keyId, String plaintext) {
        if (!StringUtils.hasText(keyId)) {
            throw new IllegalArgumentException("keyId must not be blank");
        }
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }

        Optional<SecretKey> keyOpt = keyManager.getKey(keyId);
        SecretKey secretKey = keyOpt.orElseGet(() -> keyManager.generateKey(keyId));

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

            String hexCiphertext = HexFormat.of().formatHex(ciphertextBytes);
            String hexIv = HexFormat.of().formatHex(iv);

            return EncryptedEnvelope.of(keyId, hexCiphertext, hexIv);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts an {@link EncryptedEnvelope} back into its plaintext representation.
     *
     * @param envelope the encrypted envelope
     * @return the decrypted UTF-8 plaintext string
     * @throws KeyDestroyedException if the key was permanently destroyed (crypto-shredded)
     * @throws IllegalStateException if decryption fails due to invalid tag or corrupted ciphertext
     */
    public String decrypt(EncryptedEnvelope envelope) {
        if (envelope == null || !StringUtils.hasText(envelope.keyId())) {
            throw new IllegalArgumentException("Envelope or keyId must not be null/blank");
        }

        Optional<SecretKey> keyOpt = keyManager.getKey(envelope.keyId());
        if (keyOpt.isEmpty()) {
            throw new KeyDestroyedException(envelope.keyId());
        }

        SecretKey secretKey = keyOpt.get();
        byte[] iv = HexFormat.of().parseHex(envelope.iv());
        byte[] ciphertext = HexFormat.of().parseHex(envelope.ciphertext());

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed (authentication tag mismatch or corrupted ciphertext): "
                    + e.getMessage(), e);
        }
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }
}
