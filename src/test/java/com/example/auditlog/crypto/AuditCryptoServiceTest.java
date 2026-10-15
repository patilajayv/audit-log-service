package com.example.auditlog.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuditCryptoServiceTest {

    private InMemoryKeyManager keyManager;
    private AuditCryptoService cryptoService;

    @BeforeEach
    void setUp() {
        keyManager = new InMemoryKeyManager();
        cryptoService = new AuditCryptoService(keyManager);
    }

    @Test
    void encryptAndDecryptRoundTripSucceeds() {
        String keyId = "test-dek-1";
        String plaintext = "confidential-account-987654";

        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, plaintext);

        assertThat(envelope.type()).isEqualTo("EncryptedEnvelope");
        assertThat(envelope.algorithm()).isEqualTo("AES-256-GCM");
        assertThat(envelope.keyId()).isEqualTo(keyId);
        assertThat(envelope.keyScope()).isEqualTo("EVENT_FIELD");
        assertThat(envelope.ciphertext()).isNotBlank();
        assertThat(envelope.iv()).hasSize(24); // 12 bytes hex = 24 chars
        assertThat(envelope.ciphertext()).isNotEqualTo(plaintext);

        String decrypted = cryptoService.decrypt(envelope);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void decryptThrowsKeyDestroyedExceptionWhenKeyIsDestroyed() {
        String keyId = "test-dek-to-destroy";
        String plaintext = "ssn-000-12-3456";

        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, plaintext);
        assertThat(keyManager.isKeyActive(keyId)).isTrue();
        assertThat(keyManager.isKeyDestroyed(keyId)).isFalse();

        boolean destroyed = keyManager.destroyKey(keyId);
        assertThat(destroyed).isTrue();
        assertThat(keyManager.isKeyActive(keyId)).isFalse();
        assertThat(keyManager.isKeyDestroyed(keyId)).isTrue();

        assertThatThrownBy(() -> cryptoService.decrypt(envelope))
                .isInstanceOf(KeyDestroyedException.class)
                .hasMessageContaining(keyId);
    }

    @Test
    void decryptThrowsOnTamperedCiphertext() {
        String keyId = "test-dek-tamper";
        String plaintext = "immutable-data";

        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, plaintext);

        // Tamper ciphertext
        String tamperedCiphertext = envelope.ciphertext().substring(0, envelope.ciphertext().length() - 2) + "00";
        EncryptedEnvelope tamperedEnvelope = new EncryptedEnvelope(
                envelope.type(),
                envelope.algorithm(),
                envelope.keyId(),
                tamperedCiphertext,
                envelope.iv(),
                envelope.keyScope());

        assertThatThrownBy(() -> cryptoService.decrypt(tamperedEnvelope))
                .isInstanceOf(IllegalStateException.class)
                .hasCauseInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void decryptThrowsOnTamperedIv() {
        String keyId = "test-dek-iv-tamper";
        String plaintext = "payload-data";

        EncryptedEnvelope envelope = cryptoService.encrypt(keyId, plaintext);

        String tamperedIv = "0".repeat(24);
        EncryptedEnvelope tamperedEnvelope = new EncryptedEnvelope(
                envelope.type(),
                envelope.algorithm(),
                envelope.keyId(),
                envelope.ciphertext(),
                tamperedIv,
                envelope.keyScope());

        assertThatThrownBy(() -> cryptoService.decrypt(tamperedEnvelope))
                .isInstanceOf(IllegalStateException.class)
                .hasCauseInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void keyManagerDestroyIsIdempotent() {
        String keyId = "idempotent-key";
        keyManager.generateKey(keyId);

        assertThat(keyManager.destroyKey(keyId)).isTrue();
        assertThat(keyManager.destroyKey(keyId)).isFalse();
    }
}
