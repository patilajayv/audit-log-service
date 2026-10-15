package com.example.auditlog.export;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.hashing.CanonicalEventContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link StandaloneExportVerifier} verifying cryptographic tamper detection,
 * sequence contiguity, witness verification, and chain-head alignment.
 */
class StandaloneExportVerifierTest {

    private AuditHashService hashService;
    private StandaloneExportVerifier verifier;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        this.hashService = new AuditHashService();
        this.verifier = new StandaloneExportVerifier(hashService);
        this.objectMapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Empty chain bundle verifies as INTACT")
    void emptyChainVerifiesIntact() {
        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T14:00:00.000Z",
                new ExportFilterDto("ACTOR_ID", "user-1", true),
                new ExportChainHeadDto(0L, AuditHashService.GENESIS_HASH),
                new ExportSummaryDto(0L, null, null, 0L),
                Collections.emptyList(),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.recordsVerified()).isEqualTo(0L);
        assertThat(result.matchedEventsVerified()).isEqualTo(0L);
    }

    @Test
    @DisplayName("Valid bundle with mixed matched events and witnesses verifies as INTACT")
    void validMixedBundleVerifiesIntact() {
        // Construct a synthetic 3-event chain:
        // seq 1: witness (user-bob)
        // seq 2: matched event (user-alice)
        // seq 3: witness (user-charlie)
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        Instant t2 = Instant.parse("2026-10-15T12:01:00.000Z");
        Instant t3 = Instant.parse("2026-10-15T12:02:00.000Z");

        // Event 1 (Witness)
        String c1 = hashService.computeContentHash(new CanonicalEventContent(
                "JCS-1", UUID.randomUUID(), "LOGIN", "bob", "SYSTEM", "sys",
                objectMapper.createObjectNode().put("v", 1), null, t1));
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        // Event 2 (Matched)
        UUID e2Id = UUID.randomUUID();
        ObjectNode p2 = objectMapper.createObjectNode().put("orderId", 123);
        CanonicalEventContent c2Content = new CanonicalEventContent(
                "JCS-1", e2Id, "ORDER", "alice", "ORDER", "ord-123", p2, null, t2);
        String c2 = hashService.computeContentHash(c2Content);
        String r2 = hashService.computeRecordHash(2L, r1, c2);

        // Event 3 (Witness)
        String c3 = hashService.computeContentHash(new CanonicalEventContent(
                "JCS-1", UUID.randomUUID(), "LOGOUT", "charlie", "SYSTEM", "sys",
                objectMapper.createObjectNode().put("v", 3), null, t3));
        String r3 = hashService.computeRecordHash(3L, r2, c3);

        ExportEventDto event2 = new ExportEventDto(
                2L, e2Id, "ORDER", "alice", "ORDER", "ord-123", p2,
                null, hashService.formatTimestamp(t2), "JCS-1", c2, r1, r2, null);

        ExportWitnessDto witness1 = new ExportWitnessDto(1L, AuditHashService.GENESIS_HASH, c1, r1);
        ExportWitnessDto witness3 = new ExportWitnessDto(3L, r2, c3, r3);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(3L, r3),
                new ExportSummaryDto(1L, 2L, 2L, 2L),
                List.of(event2),
                List.of(witness1, witness3)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.recordsVerified()).isEqualTo(3L);
        assertThat(result.matchedEventsVerified()).isEqualTo(1L);
    }

    @Test
    @DisplayName("Tampered payload in matched event fails with content hash mismatch")
    void tamperedPayloadFailsContentHash() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();
        ObjectNode originalPayload = objectMapper.createObjectNode().put("amount", 100);
        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1", e1Id, "DEPOSIT", "alice", "ACCOUNT", "acc-1", originalPayload, null, t1);
        String c1 = hashService.computeContentHash(content);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        // Tamper with payload
        ObjectNode tamperedPayload = objectMapper.createObjectNode().put("amount", 999999);

        ExportEventDto event1 = new ExportEventDto(
                1L, e1Id, "DEPOSIT", "alice", "ACCOUNT", "acc-1", tamperedPayload,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(event1),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(1L);
        assertThat(result.failureReason()).contains("Content hash mismatch at sequence 1");
    }

    @Test
    @DisplayName("Missing intermediate sequence fails with sequence gap")
    void missingSequenceFailsSequenceGap() {
        // seq 1 witness with valid record hash, seq 3 witness (seq 2 omitted)
        String c1 = "c1".repeat(32);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);
        ExportWitnessDto witness1 = new ExportWitnessDto(1L, AuditHashService.GENESIS_HASH, c1, r1);
        ExportWitnessDto witness3 = new ExportWitnessDto(3L, "r2", "c3", "r3");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(3L, "r3"),
                new ExportSummaryDto(0L, null, null, 2L),
                Collections.emptyList(),
                List.of(witness1, witness3)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(2L);
        assertThat(result.failureReason()).contains("Sequence gap: sequence 2 is missing");
    }

    @Test
    @DisplayName("Tampered witness record hash fails verification")
    void tamperedWitnessHashFails() {
        ExportWitnessDto witness1 = new ExportWitnessDto(1L, AuditHashService.GENESIS_HASH, "c1", "faked_record_hash");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, "faked_record_hash"),
                new ExportSummaryDto(0L, null, null, 1L),
                Collections.emptyList(),
                List.of(witness1)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(1L);
        assertThat(result.failureReason()).contains("Record hash mismatch at sequence 1");
    }

    @Test
    @DisplayName("Tampered chain head hash fails with chain head mismatch")
    void tamperedChainHeadFails() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();
        ObjectNode p1 = objectMapper.createObjectNode().put("test", true);
        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1", e1Id, "TEST", "alice", "SYS", "s1", p1, null, t1);
        String c1 = hashService.computeContentHash(content);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        ExportEventDto event1 = new ExportEventDto(
                1L, e1Id, "TEST", "alice", "SYS", "s1", p1,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null);

        // Falsified head record hash
        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, "faked_head_record_hash"),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(event1),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureReason()).contains("Chain head record hash mismatch");
    }

    @Test
    @DisplayName("Event actorId mismatch with filter criteria fails verification")
    void eventFilterMismatchFails() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();
        ObjectNode p1 = objectMapper.createObjectNode().put("test", true);
        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1", e1Id, "TEST", "bob", "SYS", "s1", p1, null, t1);
        String c1 = hashService.computeContentHash(content);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        ExportEventDto event1 = new ExportEventDto(
                1L, e1Id, "TEST", "bob", "SYS", "s1", p1,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(event1),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureReason()).contains("does not match filter 'alice'");
    }

    @Test
    @DisplayName("Legacy masked event returns PARTIALLY_VERIFIED_REDACTED with verified chain linkage")
    void legacyMaskedEventReturnsPartiallyVerifiedRedacted() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();
        // Original payload at ingestion time
        ObjectNode originalPayload = objectMapper.createObjectNode()
                .put("ssn", "999-88-7777")
                .put("name", "Alice");
        CanonicalEventContent originalContent = new CanonicalEventContent(
                "JCS-1", e1Id, "ENROLL", "alice", "USER", "u1", originalPayload, null, t1);
        String c1 = hashService.computeContentHash(originalContent);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        // Exported masked projection
        ObjectNode maskedPayload = objectMapper.createObjectNode()
                .put("ssn", "[REDACTED]")
                .put("name", "Alice");

        ExportEventDto maskedEvent = new ExportEventDto(
                1L, e1Id, "ENROLL", "alice", "USER", "u1", maskedPayload,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null, "MASKED");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(maskedEvent),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.PARTIALLY_VERIFIED_REDACTED);
        assertThat(result.recordsVerified()).isEqualTo(1L);
        assertThat(result.matchedEventsVerified()).isEqualTo(0L);
        assertThat(result.maskedEventsCount()).isEqualTo(1L);
    }

    @Test
    @DisplayName("Crypto-shredded event with EncryptedEnvelope returns INTACT and 100% content verified")
    void cryptoShreddedEventReturnsIntact() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();

        ObjectNode envelopeNode = objectMapper.createObjectNode()
                .put("@type", "EncryptedEnvelope")
                .put("algorithm", "AES-256-GCM")
                .put("keyId", "key-123")
                .put("iv", "dGVzdGl2MTIzNA==")
                .put("ciphertext", "Y2lwaGVydGV4dGRhdGE=");

        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("secretData", envelopeNode);

        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1", e1Id, "SECURE_ACTION", "alice", "DATA", "d1", payload, null, t1);
        String c1 = hashService.computeContentHash(content);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        ExportEventDto shreddedEvent = new ExportEventDto(
                1L, e1Id, "SECURE_ACTION", "alice", "DATA", "d1", payload,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null, "CRYPTO_SHREDDED");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(shreddedEvent),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.INTACT);
        assertThat(result.recordsVerified()).isEqualTo(1L);
        assertThat(result.matchedEventsVerified()).isEqualTo(1L);
        assertThat(result.maskedEventsCount()).isEqualTo(0L);
    }

    @Test
    @DisplayName("Tampered ciphertext in crypto-shredded event fails verification with content hash mismatch")
    void tamperedCryptoShreddedEnvelopeFailsContentHash() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();

        ObjectNode envelopeNode = objectMapper.createObjectNode()
                .put("@type", "EncryptedEnvelope")
                .put("algorithm", "AES-256-GCM")
                .put("keyId", "key-123")
                .put("iv", "dGVzdGl2MTIzNA==")
                .put("ciphertext", "Y2lwaGVydGV4dGRhdGE=");

        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("secretData", envelopeNode);

        CanonicalEventContent content = new CanonicalEventContent(
                "JCS-1", e1Id, "SECURE_ACTION", "alice", "DATA", "d1", payload, null, t1);
        String c1 = hashService.computeContentHash(content);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        // Tamper ciphertext
        ObjectNode tamperedEnvelope = envelopeNode.deepCopy();
        tamperedEnvelope.put("ciphertext", "dGFtcGVyZWRjaXBoZXI=");
        ObjectNode tamperedPayload = objectMapper.createObjectNode();
        tamperedPayload.set("secretData", tamperedEnvelope);

        ExportEventDto tamperedEvent = new ExportEventDto(
                1L, e1Id, "SECURE_ACTION", "alice", "DATA", "d1", tamperedPayload,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, AuditHashService.GENESIS_HASH, r1, null, "CRYPTO_SHREDDED");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(tamperedEvent),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureReason()).contains("Content hash mismatch at sequence 1");
    }

    @Test
    @DisplayName("Tampered previousHash in legacy masked event fails with previous hash mismatch")
    void tamperedLinkageInMaskedEventFails() {
        Instant t1 = Instant.parse("2026-10-15T12:00:00.000Z");
        UUID e1Id = UUID.randomUUID();
        ObjectNode maskedPayload = objectMapper.createObjectNode().put("ssn", "[REDACTED]");
        String c1 = "c1".repeat(32);
        String r1 = hashService.computeRecordHash(1L, AuditHashService.GENESIS_HASH, c1);

        // Tamper previous hash
        ExportEventDto tamperedEvent = new ExportEventDto(
                1L, e1Id, "ENROLL", "alice", "USER", "u1", maskedPayload,
                null, hashService.formatTimestamp(t1), "JCS-1", c1, "faked_prev_hash", r1, null, "MASKED");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(1L, r1),
                new ExportSummaryDto(1L, 1L, 1L, 0L),
                List.of(tamperedEvent),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureReason()).contains("Previous hash mismatch at sequence 1");
    }

    @Test
    @DisplayName("Event sequence number greater than chain head is rejected as CORRUPTED")
    void eventSequenceGreaterThanHeadFails() {
        ObjectNode p1 = objectMapper.createObjectNode().put("v", 1);
        ExportEventDto event = new ExportEventDto(
                5L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(1L, 5L, 5L, 0L),
                List.of(event),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(5L);
        assertThat(result.failureReason()).contains("Event sequence number 5 is outside valid range [1, 2]");
    }

    @Test
    @DisplayName("Event sequence number zero or negative is rejected as CORRUPTED")
    void eventSequenceZeroOrNegativeFails() {
        ObjectNode p1 = objectMapper.createObjectNode().put("v", 1);
        ExportEventDto event = new ExportEventDto(
                0L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(1L, 0L, 0L, 0L),
                List.of(event),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(0L);
        assertThat(result.failureReason()).contains("Event sequence number 0 is outside valid range [1, 2]");
    }

    @Test
    @DisplayName("Witness sequence number outside valid range is rejected as CORRUPTED")
    void witnessSequenceOutOfBoundsFails() {
        ExportWitnessDto witness = new ExportWitnessDto(99L, "p0", "c1", "r1");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(0L, null, null, 1L),
                Collections.emptyList(),
                List.of(witness)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(99L);
        assertThat(result.failureReason()).contains("Witness sequence number 99 is outside valid range [1, 2]");
    }

    @Test
    @DisplayName("Duplicate event sequence numbers are rejected as CORRUPTED")
    void duplicateEventSequenceFails() {
        ObjectNode p1 = objectMapper.createObjectNode().put("v", 1);
        ExportEventDto ev1 = new ExportEventDto(
                1L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);
        ExportEventDto ev2 = new ExportEventDto(
                1L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(2L, 1L, 1L, 0L),
                List.of(ev1, ev2),
                Collections.emptyList()
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(1L);
        assertThat(result.failureReason()).contains("Duplicate event sequence number: 1");
    }

    @Test
    @DisplayName("Duplicate witness sequence numbers are rejected as CORRUPTED")
    void duplicateWitnessSequenceFails() {
        ExportWitnessDto w1 = new ExportWitnessDto(1L, "p0", "c1", "r1");
        ExportWitnessDto w2 = new ExportWitnessDto(1L, "p0", "c1", "r1");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(0L, null, null, 2L),
                Collections.emptyList(),
                List.of(w1, w2)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(1L);
        assertThat(result.failureReason()).contains("Duplicate witness sequence number: 1");
    }

    @Test
    @DisplayName("Sequence number collision across events and witnesses is rejected as CORRUPTED")
    void duplicateSequenceAcrossEventsAndWitnessesFails() {
        ObjectNode p1 = objectMapper.createObjectNode().put("v", 1);
        ExportEventDto ev = new ExportEventDto(
                1L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);
        ExportWitnessDto wt = new ExportWitnessDto(1L, "p0", "c1", "r1");

        ExportBundleDto bundle = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(1L, 1L, 1L, 1L),
                List.of(ev),
                List.of(wt)
        );

        StandaloneExportVerifier.ExportVerificationResult result = verifier.verify(bundle);
        assertThat(result.status()).isEqualTo(StandaloneExportVerifier.Status.CORRUPTED);
        assertThat(result.failureSequenceNo()).isEqualTo(1L);
        assertThat(result.failureReason()).contains("Sequence number appears in both events and witnesses: 1");
    }

    @Test
    @DisplayName("Python verifier script rejects out-of-range and duplicate sequence numbers with exit code 1")
    void pythonVerifierRejectsOutOfRangeAndDuplicates() throws Exception {
        // 1. Test out-of-range event sequence in Python verifier
        ObjectNode p1 = objectMapper.createObjectNode().put("v", 1);
        ExportEventDto outOfRangeEvent = new ExportEventDto(
                99L, UUID.randomUUID(), "TEST", "alice", "RES", "r1", p1,
                null, "2026-10-15T12:00:00.000Z", "JCS-1", "c1", "p0", "r1", null);

        ExportBundleDto bundleOutOfRange = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(1L, 99L, 99L, 0L),
                List.of(outOfRangeEvent),
                Collections.emptyList()
        );

        Path tempFile = Files.createTempFile("test-oor-", ".json");
        try {
            objectMapper.writeValue(tempFile.toFile(), bundleOutOfRange);
            ProcessBuilder pb = new ProcessBuilder("python3", "scripts/verify_export.py", tempFile.toAbsolutePath().toString());
            Process process = pb.start();
            int exitCode = process.waitFor();
            BufferedReader stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String errStr = stderr.lines().reduce("", (a, b) -> a + "\n" + b);

            assertThat(exitCode).isEqualTo(1);
            assertThat(errStr).contains("outside valid range [1, 2]");
        } finally {
            Files.deleteIfExists(tempFile);
        }

        // 2. Test duplicate sequence in Python verifier
        ExportWitnessDto w1 = new ExportWitnessDto(1L, "p0", "c1", "r1");
        ExportWitnessDto w2 = new ExportWitnessDto(1L, "p0", "c1", "r1");

        ExportBundleDto bundleDuplicate = new ExportBundleDto(
                "1.0",
                UUID.randomUUID(),
                "2026-10-15T12:05:00.000Z",
                new ExportFilterDto("ACTOR_ID", "alice", true),
                new ExportChainHeadDto(2L, "headhash"),
                new ExportSummaryDto(0L, null, null, 2L),
                Collections.emptyList(),
                List.of(w1, w2)
        );

        Path tempFileDup = Files.createTempFile("test-dup-", ".json");
        try {
            objectMapper.writeValue(tempFileDup.toFile(), bundleDuplicate);
            ProcessBuilder pb = new ProcessBuilder("python3", "scripts/verify_export.py", tempFileDup.toAbsolutePath().toString());
            Process process = pb.start();
            int exitCode = process.waitFor();
            BufferedReader stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String errStr = stderr.lines().reduce("", (a, b) -> a + "\n" + b);

            assertThat(exitCode).isEqualTo(1);
            assertThat(errStr).contains("Duplicate witness sequence number: 1");
        } finally {
            Files.deleteIfExists(tempFileDup);
        }
    }
}
