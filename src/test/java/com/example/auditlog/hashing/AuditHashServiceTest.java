package com.example.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuditHashService} verifying strict RFC 8785 (JCS) compliance
 * and deterministic hashing against independently established test vectors.
 *
 * <p>Expected hashes and canonical JSON strings in this test suite are hardcoded constants
 * computed independently (using standard external tools such as Python hashlib and RFC 8785
 * specification reference values). Neither production code nor test-local duplicates of the
 * hashing algorithm are used as oracles.
 */
class AuditHashServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Fixed test-vector inputs
    private static final UUID FIXED_EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant FIXED_RECORDED_AT = Instant.parse("2026-10-14T15:00:01.456Z");
    private static final Instant FIXED_SOURCE_TIMESTAMP = Instant.parse("2026-10-14T15:00:00.123Z");
    private static final String GENESIS_HASH = "0".repeat(64);

    // Hardcoded independent test vectors (calculated externally via RFC 8785 rules and SHA-256)
    // Vector 1: Empty payload, with sourceTimestamp
    private static final String VECTOR1_CANONICAL_JSON =
            "{\"actorId\":\"actor-123\","
            + "\"canonicalizationVersion\":\"JCS-1\","
            + "\"eventId\":\"00000000-0000-0000-0000-000000000001\","
            + "\"eventType\":\"USER_LOGIN\","
            + "\"payload\":{},"
            + "\"recordedAt\":\"2026-10-14T15:00:01.456Z\","
            + "\"resourceId\":\"account-456\","
            + "\"resourceType\":\"ACCOUNT\","
            + "\"sourceTimestamp\":\"2026-10-14T15:00:00.123Z\"}";

    // Independently calculated: echo -n '<VECTOR1_CANONICAL_JSON>' | shasum -a 256
    private static final String VECTOR1_CONTENT_HASH =
            "4adef4d4355b8181195edbafb7dd255548eadf027fcc289c01b2cf5666530b26";

    // Independently calculated: length-prefixed SHA-256 (seq 1, genesis prev, vector1 content hash)
    // bytes: [4:15]AUDIT_RECORD_V1 + [4:1]1 + [4:64]00..00 + [4:64]4adef4...
    private static final String VECTOR1_RECORD_HASH =
            "d4fdc27004f4d0ab21f89b9259ea15175f0a7b85fcc6bfa2c0bb1713c573e00e";

    // Vector 2: Payload with numeric edge cases (integer-valued float, negative zero, exponential)
    // and absent (null) sourceTimestamp
    private static final String VECTOR2_CANONICAL_JSON =
            "{\"actorId\":\"actor-123\","
            + "\"canonicalizationVersion\":\"JCS-1\","
            + "\"eventId\":\"00000000-0000-0000-0000-000000000001\","
            + "\"eventType\":\"USER_LOGIN\","
            + "\"payload\":{\"amount\":100,\"balance\":0,\"rate\":0.000015},"
            + "\"recordedAt\":\"2026-10-14T15:00:01.456Z\","
            + "\"resourceId\":\"account-456\","
            + "\"resourceType\":\"ACCOUNT\","
            + "\"sourceTimestamp\":null}";

    private static final String VECTOR2_CONTENT_HASH =
            "2cb3116f80ec8ef08a07bd9ee3f2994d53eb67a4f4c4d7e6316a6ab08d00766e";

    private static final String VECTOR2_RECORD_HASH =
            "8e36c5147429d8a190b04f6f6978ccab1e4f23e291d81042767456de2a1a8b1a";

    private AuditHashService service;

    @BeforeEach
    void setUp() {
        service = new AuditHashService();
    }

    // -------------------------------------------------------------------------
    // Hardcoded Independent Test Vectors
    // -------------------------------------------------------------------------

    @Test
    void matchesHardcodedVector1WithSourceTimestamp() {
        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1",
                FIXED_EVENT_ID,
                "USER_LOGIN",
                "actor-123",
                "ACCOUNT",
                "account-456",
                MAPPER.createObjectNode(),
                FIXED_SOURCE_TIMESTAMP,
                FIXED_RECORDED_AT);

        String canonicalJson = service.buildCanonicalJson(content);
        assertThat(canonicalJson).isEqualTo(VECTOR1_CANONICAL_JSON);

        String contentHash = service.computeContentHash(content);
        assertThat(contentHash).isEqualTo(VECTOR1_CONTENT_HASH);

        String recordHash = service.computeRecordHash(1L, GENESIS_HASH, contentHash);
        assertThat(recordHash).isEqualTo(VECTOR1_RECORD_HASH);
    }

    @Test
    void matchesHardcodedVector2WithNumericPayloadAndNullSourceTimestamp() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("amount", 100.0);    // Integer-valued float -> must normalize to 100
        payload.put("balance", -0.0);    // Negative zero -> must normalize to 0
        payload.put("rate", 0.000015);   // 1.5e-5

        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1",
                FIXED_EVENT_ID,
                "USER_LOGIN",
                "actor-123",
                "ACCOUNT",
                "account-456",
                payload,
                null,
                FIXED_RECORDED_AT);

        String canonicalJson = service.buildCanonicalJson(content);
        assertThat(canonicalJson).isEqualTo(VECTOR2_CANONICAL_JSON);

        String contentHash = service.computeContentHash(content);
        assertThat(contentHash).isEqualTo(VECTOR2_CONTENT_HASH);

        String recordHash = service.computeRecordHash(2L, VECTOR1_CONTENT_HASH, contentHash);
        assertThat(recordHash).isEqualTo(VECTOR2_RECORD_HASH);
    }

    // -------------------------------------------------------------------------
    // IEEE-754 Number Handling (RFC 8785 §3.2.2.3 & Appendix B)
    // -------------------------------------------------------------------------

    @Test
    void normalizesNegativeZeroToZero() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("negZero", -0.0);
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"payload\":{\"negZero\":0}");
    }

    @Test
    void normalizesIntegerValuedFloatsWithoutDecimals() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("intFloat1", 100.0);
        payload.put("intFloat2", 1.0);
        payload.put("intFloat3", 0.0);
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"payload\":{\"intFloat1\":100,\"intFloat2\":1,\"intFloat3\":0}");
    }

    @Test
    void formatsExponentsWithLowercaseEAndExplicitPlus() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("large1", 1e21);
        payload.put("large2", 1e23);
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"large1\":1e+21");
        assertThat(json).contains("\"large2\":1e+23");
    }

    @Test
    void respectsOneInMillionExponentBoundary() {
        // RFC 8785 Table 1: 0.000001 (1e-6) is serialized in decimal; 9.999999999999997e-7 uses exponent
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("decimalBoundary", 0.000001);
        payload.put("expBoundary", 1e-7);
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"decimalBoundary\":0.000001");
        assertThat(json).contains("\"expBoundary\":1e-7");
    }

    @Test
    void serializesSubnormalAndMaxFiniteIeee754ValuesCorrectly() {
        // RFC 8785 Appendix B Table 1 exact samples
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("minPos", Double.longBitsToDouble(0x0000000000000001L)); // 5e-324
        payload.put("minNeg", Double.longBitsToDouble(0x8000000000000001L)); // -5e-324
        payload.put("maxPos", Double.longBitsToDouble(0x7fefffffffffffffL)); // 1.7976931348623157e+308
        payload.put("maxNeg", Double.longBitsToDouble(0xffefffffffffffffL)); // -1.7976931348623157e+308
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"minPos\":5e-324");
        assertThat(json).contains("\"minNeg\":-5e-324");
        assertThat(json).contains("\"maxPos\":1.7976931348623157e+308");
        assertThat(json).contains("\"maxNeg\":-1.7976931348623157e+308");
    }

    // -------------------------------------------------------------------------
    // Rejection of Non-Finite Numbers (RFC 8785 §3.2.2.3)
    // -------------------------------------------------------------------------

    @Test
    void rejectsNanInPayload() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", Double.NaN);
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Non-finite numbers");
    }

    @Test
    void rejectsPositiveInfinityInPayload() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", Double.POSITIVE_INFINITY);
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Non-finite numbers");
    }

    @Test
    void rejectsNegativeInfinityInPayload() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", Double.NEGATIVE_INFINITY);
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Non-finite numbers");
    }

    // -------------------------------------------------------------------------
    // String Escaping and Unicode Property Ordering (RFC 8785 §3.2.2.2 & §3.2.3)
    // -------------------------------------------------------------------------

    @Test
    void escapesControlCharactersWithLowercaseHex() {
        // RFC 8785 §3.2.2.2: U+0000..U+001F must use lowercase \\u00xx notation
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("ctrl", "a\u000fb\u001fc");
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"ctrl\":\"a\\u000fb\\u001fc\"");
    }

    @Test
    void preservesStandardTwoCharacterEscapes() {
        // \" \\ \b \f \n \r \t
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("escapes", "quote:\" slash:\\ bs:\b ff:\f nl:\n cr:\r tab:\t");
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("quote:\\\" slash:\\\\ bs:\\b ff:\\f nl:\\n cr:\\r tab:\\t");
    }

    @Test
    void sortsPropertiesByUtf16CodeUnitsMatchingRfc8785Section323() {
        // Exact property set from RFC 8785 Section 3.2.3:
        // Expected order: \r < 1 < \u0080 < \u00f6 < \u20ac < \ud83d\ude00 < \ufb33
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("\u20ac", "Euro Sign");
        payload.put("\r", "Carriage Return");
        payload.put("\ufb33", "Hebrew Letter Dalet With Dagesh");
        payload.put("1", "One");
        payload.put("\ud83d\ude00", "Emoji: Grinning Face");
        payload.put("\u0080", "Control");
        payload.put("\u00f6", "Latin Small Letter O With Diaeresis");

        CanonicalEventContent content = minimalContent(payload);
        String json = service.buildCanonicalJson(content);

        int posCr = json.indexOf("\"\\r\"");
        int pos1 = json.indexOf("\"1\"");
        int pos80 = json.indexOf("\"\u0080\"");
        int posF6 = json.indexOf("\"\u00f6\"");
        int posEuro = json.indexOf("\"\u20ac\"");
        int posEmoji = json.indexOf("\"\ud83d\ude00\"");
        int posHebrew = json.indexOf("\"\ufb33\"");

        assertThat(posCr).isLessThan(pos1);
        assertThat(pos1).isLessThan(pos80);
        assertThat(pos80).isLessThan(posF6);
        assertThat(posF6).isLessThan(posEuro);
        assertThat(posEuro).isLessThan(posEmoji);
        assertThat(posEmoji).isLessThan(posHebrew);
    }

    // -------------------------------------------------------------------------
    // Top-Level Field Ordering and Timestamp Formatting
    // -------------------------------------------------------------------------

    @Test
    void topLevelKeysFollowRfc8785Order() {
        CanonicalEventContent content = minimalContent(MAPPER.createObjectNode());
        String json = service.buildCanonicalJson(content);

        int actorIdPos = json.indexOf("\"actorId\"");
        int canonPos = json.indexOf("\"canonicalizationVersion\"");
        int eventIdPos = json.indexOf("\"eventId\"");
        int eventTypePos = json.indexOf("\"eventType\"");
        int payloadPos = json.indexOf("\"payload\"");
        int recordedAtPos = json.indexOf("\"recordedAt\"");
        int resourceIdPos = json.indexOf("\"resourceId\"");
        int resourceTypePos = json.indexOf("\"resourceType\"");
        int sourceTimestampPos = json.indexOf("\"sourceTimestamp\"");

        assertThat(actorIdPos).isLessThan(canonPos);
        assertThat(canonPos).isLessThan(eventIdPos);
        assertThat(eventIdPos).isLessThan(eventTypePos);
        assertThat(eventTypePos).isLessThan(payloadPos);
        assertThat(payloadPos).isLessThan(recordedAtPos);
        assertThat(recordedAtPos).isLessThan(resourceIdPos);
        assertThat(resourceIdPos).isLessThan(resourceTypePos);
        assertThat(resourceTypePos).isLessThan(sourceTimestampPos);
    }

    @Test
    void truncatesNanosecondsInTimestampFormatting() {
        Instant withNanos = Instant.parse("2026-10-14T15:00:01.123456789Z");
        assertThat(service.formatTimestamp(withNanos)).isEqualTo("2026-10-14T15:00:01.123Z");
    }

    @Test
    void recordHashDiffersWhenAnyComponentChanges() {
        String contentHash = VECTOR1_CONTENT_HASH;
        String baseHash = service.computeRecordHash(1L, GENESIS_HASH, contentHash);

        assertThat(service.computeRecordHash(2L, GENESIS_HASH, contentHash)).isNotEqualTo(baseHash);
        assertThat(service.computeRecordHash(1L, "f".repeat(64), contentHash)).isNotEqualTo(baseHash);
        assertThat(service.computeRecordHash(1L, GENESIS_HASH, VECTOR2_CONTENT_HASH)).isNotEqualTo(baseHash);
    }

    // -------------------------------------------------------------------------
    // Safe Integer Range (RFC 8785 Appendix D & RFC 7493 §2.2)
    // -------------------------------------------------------------------------

    @Test
    void allowsSafeIntegersAtBoundaries() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("maxSafe", 9007199254740991L);  // 2^53 - 1
        payload.put("minSafe", -9007199254740991L); // -(2^53 - 1)
        payload.put("zero", 0L);
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"maxSafe\":9007199254740991");
        assertThat(json).contains("\"minSafe\":-9007199254740991");
        assertThat(json).contains("\"zero\":0");
    }

    @Test
    void rejectsIntegerAtPositive2Pow53() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", 9007199254740992L); // 2^53
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsIntegerAtPositive2Pow53PlusOne() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", 9007199254740993L); // 2^53 + 1
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsIntegerAtNegative2Pow53() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", -9007199254740992L); // -2^53
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsLongMaxValue() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", Long.MAX_VALUE); // 9223372036854775807L
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsLongMinValue() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("val", Long.MIN_VALUE); // -9223372036854775808L
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsBigIntegerBeyondSigned64BitRange() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("largePositive", new BigInteger("1000000000000000000000000000000"));
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsNegativeBigIntegerBeyondSigned64BitRange() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("largeNegative", new BigInteger("-1000000000000000000000000000000"));
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void rejectsBigDecimalRepresentingUnsafeInteger() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("unsafeDec", new BigDecimal("9007199254740993"));
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside safe IEEE-754 range");
    }

    @Test
    void permitsLargeNumbersWhenEncodedAsStrings() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("str2Pow53", "9007199254740993");
        payload.put("strLongMax", "9223372036854775807");
        payload.put("strBigInt", "1000000000000000000000000000000");
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"str2Pow53\":\"9007199254740993\"");
        assertThat(json).contains("\"strLongMax\":\"9223372036854775807\"");
        assertThat(json).contains("\"strBigInt\":\"1000000000000000000000000000000\"");
    }

    // -------------------------------------------------------------------------
    // High-Precision Decimals & Binary64 Behavior (RFC 8785 §3.2.2.3 & Appendix D)
    // -------------------------------------------------------------------------

    @Test
    void canonicalizesDecimalsViaIeee754Binary64PerRfc8785() {
        // High-precision decimal is canonicalized according to ECMAScript binary64 per RFC 8785 §3.2.2.3,
        // rather than preserving arbitrary digits.
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("highPrec", new BigDecimal("1.000000000000000123456789"));
        CanonicalEventContent content = minimalContent(payload);

        String json = service.buildCanonicalJson(content);
        assertThat(json).contains("\"highPrec\":1.0000000000000002");
    }

    @Test
    void rejectsOverflowingDecimalsBeyondDoubleRange() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("overflow", new BigDecimal("1e400"));
        CanonicalEventContent content = minimalContent(payload);

        assertThatThrownBy(() -> service.buildCanonicalJson(content))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Non-finite numbers");
    }

    // -------------------------------------------------------------------------
    // Duplicate Key Rejection (RFC 8785 §3.2.3 & RFC 7493 §2.3)
    // -------------------------------------------------------------------------

    @Test
    void rejectsDuplicateObjectKeysInJsonCanonicalizer() {
        String jsonWithDuplicateKeys = "{\"key\":\"value1\",\"key\":\"value2\"}";
        assertThatThrownBy(() -> service.canonicalizeJson(jsonWithDuplicateKeys))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate property: key");
    }

    private static CanonicalEventContent minimalContent(ObjectNode payload) {
        return new CanonicalEventContent(
                "JCS-1",
                FIXED_EVENT_ID,
                "USER_LOGIN",
                "actor-1",
                "ACCOUNT",
                "res-1",
                payload,
                null,
                FIXED_RECORDED_AT);
    }
}
