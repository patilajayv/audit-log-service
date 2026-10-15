package com.example.auditlog.crypto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Standard structured envelope for encrypted payload fields conforming to AES-256-GCM.
 *
 * <p>When sensitive fields are encrypted at ingestion, this structured object is placed into
 * the event payload JSON. The entire envelope is canonicalized and hashed into {@code content_hash},
 * ensuring tamper evidence over the ciphertext commitment.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record EncryptedEnvelope(
        @JsonProperty("@type") String type,
        String algorithm,
        String keyId,
        String ciphertext,
        String iv,
        String keyScope) {

    public static final String ENVELOPE_TYPE = "EncryptedEnvelope";
    public static final String DEFAULT_ALGORITHM = "AES-256-GCM";
    public static final String DEFAULT_KEY_SCOPE = "EVENT_FIELD";

    public EncryptedEnvelope {
        if (type == null) {
            type = ENVELOPE_TYPE;
        }
        if (algorithm == null) {
            algorithm = DEFAULT_ALGORITHM;
        }
        if (keyScope == null) {
            keyScope = DEFAULT_KEY_SCOPE;
        }
    }

    public static EncryptedEnvelope of(String keyId, String ciphertext, String iv) {
        return new EncryptedEnvelope(ENVELOPE_TYPE, DEFAULT_ALGORITHM, keyId, ciphertext, iv, DEFAULT_KEY_SCOPE);
    }
}
