package com.example.auditlog.redaction;

import org.springframework.util.StringUtils;

/**
 * Request payload for structured audit event redaction.
 *
 * @param fieldPath   dot-separated path to the target property within the event payload (e.g. "accountNumber")
 * @param reason      documented compliance or privacy reason (e.g. "GDPR_ARTICLE_17_RIGHT_TO_ERASURE")
 * @param requestedBy identifier of the compliance officer or authorized service initiating redaction
 */
public record RedactionRequest(
        String fieldPath,
        String reason,
        String requestedBy) {

    public RedactionRequest {
        if (!StringUtils.hasText(fieldPath)) {
            throw new IllegalArgumentException("fieldPath must not be blank");
        }
        if (!StringUtils.hasText(reason)) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        if (!StringUtils.hasText(requestedBy)) {
            throw new IllegalArgumentException("requestedBy must not be blank");
        }
        fieldPath = fieldPath.trim();
        reason = reason.trim();
        requestedBy = requestedBy.trim();
    }
}
