package com.example.auditlog.hashing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.stereotype.Service;

/**
 * Computes deterministic SHA-256 hashes for audit events.
 *
 * <h2>Canonicalization version {@code JCS-1}</h2>
 *
 * <p>{@code content_hash} is the SHA-256 digest of the UTF-8 bytes of the RFC 8785 JSON
 * Canonicalization Scheme (JCS) representation of the canonical event object.
 * Canonicalization is performed using {@link JsonCanonicalizer}, which strictly implements:
 * <ul>
 *   <li>IEEE 754 double precision serialization conforming to ECMAScript 6 (RFC 8785 §3.2.2.3),
 *       including normalization of -0.0 to 0, integer-valued floats without decimals,
 *       and lowercase scientific notation (e.g. {@code 1e+21}).
 *   <li>Lexicographic sorting of object properties by UTF-16 code units (RFC 8785 §3.2.3).
 *   <li>Strict string escaping (RFC 8785 §3.2.2.2), including lowercase hex {@code \\u00xx} escapes.
 *   <li>Rejection of non-finite numbers (NaN, Infinity).
 * </ul>
 *
 * <h2>Record hash</h2>
 *
 * <p>{@code record_hash} is SHA-256 of the concatenation of length-prefixed UTF-8 byte sequences
 * for four components in this order:
 *
 * <ol>
 *   <li>The literal ASCII string {@code AUDIT_RECORD_V1}
 *   <li>The decimal string representation of the sequence number
 *   <li>The lowercase hex {@code previous_hash}
 *   <li>The lowercase hex {@code content_hash}
 * </ol>
 *
 * <p>Each component is prefixed with its 4-byte big-endian unsigned length in bytes, eliminating
 * field-boundary ambiguity.
 *
 * <h2>Genesis hash</h2>
 *
 * <p>The first event uses {@code previous_hash} = {@code "0".repeat(64)}.
 */
@Service
public class AuditHashService {

    /** Genesis previous-hash value for the first event in the chain. */
    public static final String GENESIS_HASH = "0".repeat(64);

    /**
     * Timestamp format: ISO-8601 UTC with millisecond precision and 'Z' suffix.
     * Example: {@code 2026-10-14T15:00:01.456Z}
     */
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                    .withZone(ZoneOffset.UTC);

    private static final String CANONICALIZATION_VERSION = "JCS-1";
    private static final String RECORD_DOMAIN_SEPARATOR = "AUDIT_RECORD_V1";

    /**
     * Maximum safe integer in IEEE-754 double precision (2^53 - 1 = 9,007,199,254,740,991).
     * RFC 8785 Appendix D & RFC 7493 (I-JSON §2.2).
     */
    public static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;

    /**
     * Minimum safe integer in IEEE-754 double precision (-(2^53 - 1) = -9,007,199,254,740,991).
     * RFC 8785 Appendix D & RFC 7493 (I-JSON §2.2).
     */
    public static final long MIN_SAFE_INTEGER = -9_007_199_254_740_991L;

    private static final java.math.BigInteger MAX_SAFE_INTEGER_BI = java.math.BigInteger.valueOf(MAX_SAFE_INTEGER);
    private static final java.math.BigInteger MIN_SAFE_INTEGER_BI = java.math.BigInteger.valueOf(MIN_SAFE_INTEGER);

    private final ObjectMapper objectMapper;

    public AuditHashService() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    /**
     * Canonicalizes any raw JSON string according to RFC 8785 (JCS).
     *
     * @param rawJson valid JSON string
     * @return canonical JSON string
     * @throws IllegalArgumentException if the JSON is malformed, contains duplicate properties,
     *                                  or violates RFC 8785 rules
     */
    public String canonicalizeJson(String rawJson) {
        try {
            return new JsonCanonicalizer(rawJson).getEncodedString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to canonicalize JSON per RFC 8785: " + e.getMessage(), e);
        }
    }

    /**
     * Computes the {@code content_hash} for the given canonical event content.
     *
     * @param content the canonical event fields
     * @return 64-character lowercase hex SHA-256 digest
     */
    public String computeContentHash(CanonicalEventContent content) {
        String canonicalJson = buildCanonicalJson(content);
        return sha256Hex(canonicalJson.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes the {@code record_hash} from the chain position and event hashes.
     *
     * @param sequenceNo the event's sequence number (must be &gt;= 1)
     * @param previousHash the 64-char hex hash of the preceding record (or genesis hash for seq 1)
     * @param contentHash the 64-char hex content hash for this event
     * @return 64-character lowercase hex SHA-256 digest
     */
    public String computeRecordHash(long sequenceNo, String previousHash, String contentHash) {
        byte[] domainBytes = RECORD_DOMAIN_SEPARATOR.getBytes(StandardCharsets.UTF_8);
        byte[] sequenceBytes = Long.toString(sequenceNo).getBytes(StandardCharsets.UTF_8);
        byte[] previousHashBytes = previousHash.getBytes(StandardCharsets.UTF_8);
        byte[] contentHashBytes = contentHash.getBytes(StandardCharsets.UTF_8);

        MessageDigest digest = sha256Digest();
        appendLengthPrefixed(digest, domainBytes);
        appendLengthPrefixed(digest, sequenceBytes);
        appendLengthPrefixed(digest, previousHashBytes);
        appendLengthPrefixed(digest, contentHashBytes);
        return HexFormat.of().formatHex(digest.digest());
    }

    /**
     * Produces the RFC 8785 JCS canonical JSON string for the given content.
     *
     * @param content the canonical event fields
     * @return deterministic JCS canonical JSON string
     * @throws IllegalArgumentException if the content contains non-finite numbers, unsafe integers, or invalid JSON
     */
    public String buildCanonicalJson(CanonicalEventContent content) {
        validatePayload(content.payload());

        ObjectNode node = objectMapper.createObjectNode();
        node.put("actorId", content.actorId());
        node.put("canonicalizationVersion", content.canonicalizationVersion());
        node.put("eventId", content.eventId().toString());
        node.put("eventType", content.eventType());
        node.set("payload", content.payload());
        node.put("recordedAt", formatTimestamp(content.recordedAt()));
        node.put("resourceId", content.resourceId());
        node.put("resourceType", content.resourceType());
        if (content.sourceTimestamp() != null) {
            node.put("sourceTimestamp", formatTimestamp(content.sourceTimestamp()));
        } else {
            node.putNull("sourceTimestamp");
        }

        try {
            String rawJson = objectMapper.writeValueAsString(node);
            return new JsonCanonicalizer(rawJson).getEncodedString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to canonicalize event JSON per RFC 8785: " + e.getMessage(), e);
        }
    }

    /**
     * Formats an {@link Instant} as {@code YYYY-MM-DDTHH:mm:ss.SSSZ} (UTC, millisecond precision).
     * The instant is truncated to milliseconds before formatting.
     */
    public String formatTimestamp(Instant instant) {
        return TIMESTAMP_FORMAT.format(instant.truncatedTo(ChronoUnit.MILLIS));
    }

    /**
     * Recursively validates that numeric values in the payload comply with RFC 8785 and I-JSON (RFC 7493):
     * <ul>
     *   <li>Non-finite numbers (NaN, Infinity, -Infinity) are rejected (RFC 8785 §3.2.2.3).
     *   <li>Integers outside the safe IEEE-754 range [-(2^53 - 1), 2^53 - 1] are rejected (RFC 8785 Appendix D,
     *       RFC 7493 §2.2). Callers requiring exact 64-bit or arbitrary-precision integers must encode them as strings.
     *   <li>Floating-point numbers overflowing IEEE-754 binary64 range are rejected as non-finite.
     * </ul>
     */
    private void validatePayload(JsonNode node) {
        if (node == null) {
            return;
        }
        if (node.isIntegralNumber()) {
            if (node.isBigInteger()) {
                java.math.BigInteger bi = node.bigIntegerValue();
                if (bi.compareTo(MIN_SAFE_INTEGER_BI) < 0 || bi.compareTo(MAX_SAFE_INTEGER_BI) > 0) {
                    throw new IllegalArgumentException(
                            "Integer " + bi + " is outside safe IEEE-754 range [-(2^53-1), 2^53-1]; encode as string per RFC 8785 Appendix D / RFC 7493");
                }
            } else {
                long val = node.longValue();
                if (val < MIN_SAFE_INTEGER || val > MAX_SAFE_INTEGER) {
                    throw new IllegalArgumentException(
                            "Integer " + val + " is outside safe IEEE-754 range [-(2^53-1), 2^53-1]; encode as string per RFC 8785 Appendix D / RFC 7493");
                }
            }
        } else if (node.isFloatingPointNumber()) {
            double d = node.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("Non-finite numbers (NaN, Infinity) are prohibited by RFC 8785");
            }
            if (node.isBigDecimal()) {
                java.math.BigDecimal bd = node.decimalValue();
                if (bd.scale() <= 0 || bd.remainder(java.math.BigDecimal.ONE).compareTo(java.math.BigDecimal.ZERO) == 0) {
                    try {
                        java.math.BigInteger bi = bd.toBigIntegerExact();
                        if (bi.compareTo(MIN_SAFE_INTEGER_BI) < 0 || bi.compareTo(MAX_SAFE_INTEGER_BI) > 0) {
                            throw new IllegalArgumentException(
                                    "Integer " + bi + " is outside safe IEEE-754 range [-(2^53-1), 2^53-1]; encode as string per RFC 8785 Appendix D / RFC 7493");
                        }
                    } catch (ArithmeticException ignored) {
                        // Non-integral decimal
                    }
                }
            }
        } else if (node.isObject()) {
            node.elements().forEachRemaining(this::validatePayload);
        } else if (node.isArray()) {
            node.elements().forEachRemaining(this::validatePayload);
        }
    }

    /**
     * Updates the digest with a 4-byte big-endian length prefix followed by the data bytes.
     */
    private static void appendLengthPrefixed(MessageDigest digest, byte[] data) {
        int length = data.length;
        digest.update((byte) ((length >>> 24) & 0xFF));
        digest.update((byte) ((length >>> 16) & 0xFF));
        digest.update((byte) ((length >>> 8) & 0xFF));
        digest.update((byte) (length & 0xFF));
        digest.update(data);
    }

    private static String sha256Hex(byte[] data) {
        return HexFormat.of().formatHex(sha256Digest().digest(data));
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
