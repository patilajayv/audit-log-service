package com.example.auditlog.verify;

import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.hashing.CanonicalEventContent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for end-to-end cryptographic and structural audit chain verification.
 *
 * <p>Validates sequence contiguity, genesis linkage, RFC 8785 canonical content hashes,
 * SHA-256 record hashes, and chain-head pointer alignment.
 *
 * <p>Executes strictly within a read-only transaction using PostgreSQL cursor-based streaming
 * ({@code fetchSize = 500}) to avoid loading large datasets into memory. Scans stop immediately
 * upon discovering the first inconsistency.
 */
@Service
public class AuditVerificationService {

    private static final Logger log = LoggerFactory.getLogger(AuditVerificationService.class);

    private static final String SELECT_HEAD_SQL =
            "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1";

    private static final String STREAM_EVENTS_SQL = """
            SELECT sequence_no, event_id, event_type, actor_id, resource_type, resource_id,
                   payload, source_timestamp, recorded_at, canonicalization_version,
                   content_hash, previous_hash, record_hash
            FROM audit_event
            ORDER BY sequence_no ASC
            """;

    private final JdbcTemplate jdbc;
    private final AuditHashService hashService;
    private final ObjectMapper objectMapper;

    public AuditVerificationService(
            JdbcTemplate jdbc,
            AuditHashService hashService,
            ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.hashService = hashService;
        this.objectMapper = objectMapper;
    }

    /**
     * Inspects the global audit chain and returns its integrity status.
     *
     * @return {@link AuditVerificationResponse} with status {@code "INTACT"} or {@code "CORRUPTED"}
     */
    @Transactional(readOnly = true)
    public AuditVerificationResponse verifyChain() {
        // 1. Inspect the chain-head singleton record
        List<Map<String, Object>> headRows = jdbc.queryForList(SELECT_HEAD_SQL);
        if (headRows.isEmpty()) {
            log.warn("Audit chain verification failed: audit_chain_head singleton row (chain_id = 1) is missing");
            return AuditVerificationResponse.corrupted(
                    0L,
                    null,
                    null,
                    null,
                    null,
                    new ChainViolation(
                            ChainViolationType.CHAIN_HEAD_MISMATCH,
                            0L,
                            null,
                            "1 row with chain_id = 1",
                            "0 rows",
                            "audit_chain_head singleton record is missing"));
        }

        Map<String, Object> headRow = headRows.get(0);
        Long headSequenceNo = ((Number) headRow.get("last_sequence_no")).longValue();
        String headRecordHash = (String) headRow.get("last_record_hash");

        // 2. Stream and verify events in sequence order using a cursor (fetchSize = 500)
        return jdbc.query(
                conn -> {
                    PreparedStatement ps = conn.prepareStatement(
                            STREAM_EVENTS_SQL,
                            ResultSet.TYPE_FORWARD_ONLY,
                            ResultSet.CONCUR_READ_ONLY);
                    ps.setFetchSize(500);
                    return ps;
                },
                (org.springframework.jdbc.core.ResultSetExtractor<AuditVerificationResponse>)
                        rs -> processResultSet(rs, headSequenceNo, headRecordHash)
        );
    }

    private AuditVerificationResponse processResultSet(
            ResultSet rs,
            Long headSequenceNo,
            String headRecordHash) throws SQLException {

        long expectedSequence = 1L;
        String previousRecordHash = AuditHashService.GENESIS_HASH;
        long recordsVerified = 0L;
        Long lastVerifiedSequence = 0L;
        String lastVerifiedHash = AuditHashService.GENESIS_HASH;

        while (rs.next()) {
            long sequenceNo = rs.getLong("sequence_no");
            UUID eventId = (UUID) rs.getObject("event_id");
            String eventType = rs.getString("event_type");
            String actorId = rs.getString("actor_id");
            String resourceType = rs.getString("resource_type");
            String resourceId = rs.getString("resource_id");
            String payloadJson = rs.getString("payload");
            Timestamp sourceTimestamp = rs.getTimestamp("source_timestamp");
            Timestamp recordedAt = rs.getTimestamp("recorded_at");
            String canonicalizationVersion = rs.getString("canonicalization_version");
            String storedContentHash = rs.getString("content_hash");
            String storedPreviousHash = rs.getString("previous_hash");
            String storedRecordHash = rs.getString("record_hash");

            // A. Sequence Contiguity Check
            if (sequenceNo != expectedSequence) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.SEQUENCE_GAP,
                        expectedSequence,
                        eventId,
                        Long.toString(expectedSequence),
                        Long.toString(sequenceNo),
                        "Sequence gap detected: expected sequence " + expectedSequence + " but found " + sequenceNo);
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            // B. Genesis / Previous Hash Linkage Check
            if (sequenceNo == 1L) {
                if (!AuditHashService.GENESIS_HASH.equals(storedPreviousHash)) {
                    ChainViolation violation = new ChainViolation(
                            ChainViolationType.GENESIS_MISMATCH,
                            1L,
                            eventId,
                            AuditHashService.GENESIS_HASH,
                            storedPreviousHash,
                            "Genesis previous_hash mismatch at sequence 1");
                    return AuditVerificationResponse.corrupted(
                            recordsVerified, headSequenceNo, headRecordHash,
                            lastVerifiedSequence, lastVerifiedHash, violation);
                }
            } else {
                if (!previousRecordHash.equals(storedPreviousHash)) {
                    ChainViolation violation = new ChainViolation(
                            ChainViolationType.PREVIOUS_HASH_MISMATCH,
                            sequenceNo,
                            eventId,
                            previousRecordHash,
                            storedPreviousHash,
                            "Previous hash mismatch at sequence " + sequenceNo + ": broken hash chain pointer");
                    return AuditVerificationResponse.corrupted(
                            recordsVerified, headSequenceNo, headRecordHash,
                            lastVerifiedSequence, lastVerifiedHash, violation);
                }
            }

            // C. Canonical Content Hash Recomputation
            JsonNode payloadNode;
            try {
                payloadNode = objectMapper.readTree(payloadJson);
            } catch (JsonProcessingException e) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        sequenceNo,
                        eventId,
                        storedContentHash,
                        "unparseable_json",
                        "Failed to parse payload JSON for sequence " + sequenceNo + ": " + e.getMessage());
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            if (!"JCS-1".equals(canonicalizationVersion)) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        sequenceNo,
                        eventId,
                        "JCS-1",
                        canonicalizationVersion,
                        "Unsupported canonicalization version at sequence " + sequenceNo + ": " + canonicalizationVersion);
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            Instant sourceInstant = sourceTimestamp != null
                    ? sourceTimestamp.toInstant().truncatedTo(ChronoUnit.MILLIS)
                    : null;
            Instant recordedInstant = recordedAt != null
                    ? recordedAt.toInstant().truncatedTo(ChronoUnit.MILLIS)
                    : null;

            CanonicalEventContent content = new CanonicalEventContent(
                    canonicalizationVersion,
                    eventId,
                    eventType,
                    actorId,
                    resourceType,
                    resourceId,
                    payloadNode,
                    sourceInstant,
                    recordedInstant);

            String recomputedContentHash;
            try {
                recomputedContentHash = hashService.computeContentHash(content);
            } catch (IllegalArgumentException e) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        sequenceNo,
                        eventId,
                        storedContentHash,
                        "invalid_canonical_content",
                        "Payload canonicalization failed for sequence " + sequenceNo + ": " + e.getMessage());
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            if (!recomputedContentHash.equalsIgnoreCase(storedContentHash)) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        sequenceNo,
                        eventId,
                        recomputedContentHash,
                        storedContentHash,
                        "Content hash mismatch at sequence " + sequenceNo + ": stored content_hash does not match canonical payload content");
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            // D. Record Hash Recomputation
            String recomputedRecordHash = hashService.computeRecordHash(
                    sequenceNo, storedPreviousHash, storedContentHash);

            if (!recomputedRecordHash.equalsIgnoreCase(storedRecordHash)) {
                ChainViolation violation = new ChainViolation(
                        ChainViolationType.RECORD_HASH_MISMATCH,
                        sequenceNo,
                        eventId,
                        recomputedRecordHash,
                        storedRecordHash,
                        "Record hash mismatch at sequence " + sequenceNo + ": stored record_hash does not match recomputed hash");
                return AuditVerificationResponse.corrupted(
                        recordsVerified, headSequenceNo, headRecordHash,
                        lastVerifiedSequence, lastVerifiedHash, violation);
            }

            // Advance verification state
            lastVerifiedSequence = sequenceNo;
            lastVerifiedHash = storedRecordHash;
            previousRecordHash = storedRecordHash;
            recordsVerified++;
            expectedSequence++;
        }

        // 3. Final Chain Head Alignment Check
        if (headSequenceNo != recordsVerified) {
            ChainViolation violation = new ChainViolation(
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    headSequenceNo,
                    null,
                    Long.toString(headSequenceNo),
                    Long.toString(recordsVerified),
                    "Chain head sequence (" + headSequenceNo + ") does not match verified record count (" + recordsVerified + ")");
            return AuditVerificationResponse.corrupted(
                    recordsVerified, headSequenceNo, headRecordHash,
                    lastVerifiedSequence, lastVerifiedHash, violation);
        }

        if (!headRecordHash.equalsIgnoreCase(lastVerifiedHash)) {
            ChainViolation violation = new ChainViolation(
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    headSequenceNo,
                    null,
                    headRecordHash,
                    lastVerifiedHash,
                    "Chain head record hash (" + headRecordHash + ") does not match last verified record hash (" + lastVerifiedHash + ")");
            return AuditVerificationResponse.corrupted(
                    recordsVerified, headSequenceNo, headRecordHash,
                    lastVerifiedSequence, lastVerifiedHash, violation);
        }

        return AuditVerificationResponse.intact(
                recordsVerified,
                headSequenceNo,
                headRecordHash,
                lastVerifiedSequence,
                lastVerifiedHash);
    }
}
