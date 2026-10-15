package com.example.auditlog.append;

import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.hashing.CanonicalEventContent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application service that appends a validated audit event to the hash chain and manages
 * optional client-scoped idempotency and replay protection.
 *
 * <h2>Transactional protocol</h2>
 *
 * <p>All five steps execute in a single database transaction:
 *
 * <ol>
 *   <li>Lock the singleton chain-head row with {@code SELECT ... FOR UPDATE}.
 *   <li>If an {@code idempotencyKey} is present, perform lookup under the locked head row. If an
 *       identical request has already committed, return the existing event without appending or advancing head.
 *       If the key was used with a conflicting payload, throw {@link IdempotencyConflictException}.
 *   <li>Derive the next sequence number and {@code previous_hash} from the locked head.
 *   <li>Canonicalize and hash the event ({@code content_hash} and {@code record_hash}).
 *   <li>Insert the new event row and, if requested, the idempotency record.
 *   <li>Advance the chain-head row to the new sequence number and {@code record_hash}.
 * </ol>
 *
 * <p>The head-row lock serializes concurrent writers. Any failure causes a full rollback, leaving
 * the chain unchanged. The database triggers installed by the migrations provide defense-in-depth.
 */
@Service
public class AuditAppendService {

    /** Canonicalization version stored in every audit event row. */
    static final String CANONICALIZATION_VERSION = "JCS-1";

    private static final String LOCK_HEAD_SQL =
            "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1 FOR UPDATE";

    private static final String INSERT_EVENT_SQL =
            """
            INSERT INTO audit_event (
                sequence_no, event_id, event_type, actor_id, resource_type, resource_id,
                payload, source_timestamp, recorded_at,
                canonicalization_version, content_hash, previous_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?)
            """;

    private static final String ADVANCE_HEAD_SQL =
            "UPDATE audit_chain_head SET last_sequence_no = ?, last_record_hash = ? WHERE chain_id = 1";

    private static final String LOOKUP_IDEMPOTENCY_SQL =
            """
            SELECT k.request_hash, e.event_id, e.sequence_no, e.recorded_at,
                   e.content_hash, e.previous_hash, e.record_hash
            FROM audit_idempotency_key k
            JOIN audit_event e ON k.event_id = e.event_id
            WHERE k.client_id = ? AND k.idempotency_key = ?
            """;

    private static final String INSERT_IDEMPOTENCY_SQL =
            """
            INSERT INTO audit_idempotency_key (idempotency_key, client_id, request_hash, event_id)
            VALUES (?, ?, ?, ?)
            """;

    private final JdbcTemplate jdbc;
    private final AuditHashService hashService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public AuditAppendService(JdbcTemplate jdbc, AuditHashService hashService, Clock clock) {
        this.jdbc = jdbc;
        this.hashService = hashService;
        this.objectMapper = new ObjectMapper();
        this.clock = clock;
    }

    /**
     * Backward-compatible append method for non-idempotent appends.
     *
     * @param request the validated audit event request
     * @return result of the commit
     */
    @Transactional
    public AppendEventResult append(AppendEventRequest request) {
        return append(request, "anonymous", null);
    }

    /**
     * Public entry point for appending an audit event with client-scoped idempotency protection.
     *
     * <p>If an unexpected duplicate key constraint occurs on {@code audit_idempotency_key} due to a race
     * condition outside the head lock, the failed transaction is rolled back cleanly by the transaction interceptor,
     * and this method safely resolves the committed result in a fresh read-only query outside the aborted transaction.
     *
     * @param request the validated audit event request
     * @param clientId the authenticated client principal (or "anonymous")
     * @param idempotencyKey optional idempotency key
     * @return the committed or replayed event result
     */
    @Transactional
    public AppendEventResult appendWithIdempotency(AppendEventRequest request, String clientId, String idempotencyKey) {
        return append(request, clientId, idempotencyKey);
    }

    /**
     * Validates and appends an audit event to the chain in a single atomic transaction.
     *
     * @param request the event to append
     * @param clientId the authenticated client identity owning the idempotency namespace
     * @param idempotencyKey optional idempotency key
     * @return the committed or replayed event result
     */
    @Transactional
    public AppendEventResult append(AppendEventRequest request, String clientId, String idempotencyKey) {
        String effectiveClientId = (clientId != null && !clientId.isBlank()) ? clientId : "anonymous";
        String effectiveKey = (idempotencyKey != null && !idempotencyKey.isBlank()) ? idempotencyKey : null;

        String requestHash = null;
        if (effectiveKey != null) {
            requestHash = computeRequestHash(request);
        }

        // 1. Lock the chain-head row with FOR UPDATE to serialize concurrent appends.
        ChainHead head = lockAndReadHead();

        // 2. Perform idempotency check UNDER the lock before deriving sequence or inserting
        if (effectiveKey != null) {
            Optional<IdempotencyRecord> existing = findIdempotencyRecord(effectiveClientId, effectiveKey);
            if (existing.isPresent()) {
                IdempotencyRecord record = existing.get();
                if (record.requestHash().equals(requestHash)) {
                    // Identical replay: return original committed event without inserting or advancing head
                    return new AppendEventResult(
                            record.eventId(),
                            record.sequenceNo(),
                            record.recordedAt(),
                            record.contentHash(),
                            record.previousHash(),
                            record.recordHash(),
                            true);
                } else {
                    // Conflicting request: key reused with mismatched payload
                    throw new IdempotencyConflictException(
                            effectiveKey,
                            "Idempotency key '" + effectiveKey + "' has already been used with a different request payload");
                }
            }
        }

        long nextSequenceNo = head.lastSequenceNo() + 1;
        String previousHash = head.lastRecordHash();

        // 3. Assign service-side identity and timestamp (truncated to milliseconds).
        UUID eventId = UUID.randomUUID();
        Instant recordedAt = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        Instant sourceTimestamp = request.sourceTimestamp() != null
                ? request.sourceTimestamp().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)
                : null;

        // 4. Canonicalize and hash the event.
        CanonicalEventContent content = new CanonicalEventContent(
                CANONICALIZATION_VERSION,
                eventId,
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                request.payload(),
                sourceTimestamp,
                recordedAt);

        String contentHash = hashService.computeContentHash(content);
        String recordHash = hashService.computeRecordHash(nextSequenceNo, previousHash, contentHash);

        // 5. Insert the event row.
        String payloadJson = toJsonString(request.payload());
        jdbc.update(
                INSERT_EVENT_SQL,
                nextSequenceNo,
                eventId,
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                payloadJson,
                sourceTimestamp != null ? Timestamp.from(sourceTimestamp) : null,
                Timestamp.from(recordedAt),
                CANONICALIZATION_VERSION,
                contentHash,
                previousHash,
                recordHash);

        // 6. Insert idempotency record within the same atomic transaction if requested
        if (effectiveKey != null) {
            jdbc.update(INSERT_IDEMPOTENCY_SQL, effectiveKey, effectiveClientId, requestHash, eventId);
        }

        // 7. Advance the chain-head row.
        jdbc.update(ADVANCE_HEAD_SQL, nextSequenceNo, recordHash);

        return new AppendEventResult(eventId, nextSequenceNo, recordedAt, contentHash, previousHash, recordHash, false);
    }

    /**
     * Computes the deterministic RFC 8785 (JCS) canonical SHA-256 request hash over exactly:
     * {@code actorId}, {@code eventType}, {@code payload}, {@code resourceId}, {@code resourceType},
     * and {@code sourceTimestamp}.
     *
     * @param request the request to hash
     * @return 64-character lowercase hex SHA-256 digest
     */
    public String computeRequestHash(AppendEventRequest request) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("actorId", request.actorId());
        node.put("eventType", request.eventType());
        node.set("payload", request.payload());
        node.put("resourceId", request.resourceId());
        node.put("resourceType", request.resourceType());

        if (request.sourceTimestamp() != null) {
            node.put("sourceTimestamp", hashService.formatTimestamp(request.sourceTimestamp()));
        } else {
            node.putNull("sourceTimestamp");
        }

        try {
            String rawJson = objectMapper.writeValueAsString(node);
            String canonicalJson = new JsonCanonicalizer(rawJson).getEncodedString();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new IllegalStateException("Failed to compute canonical request hash: " + e.getMessage(), e);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("Failed to canonicalize request JSON per RFC 8785: " + e.getMessage(), e);
        }
    }

    private Optional<IdempotencyRecord> findIdempotencyRecord(String clientId, String idempotencyKey) {
        return jdbc.query(
                LOOKUP_IDEMPOTENCY_SQL,
                rs -> {
                    if (rs.next()) {
                        return Optional.of(new IdempotencyRecord(
                                rs.getString("request_hash"),
                                rs.getObject("event_id", UUID.class),
                                rs.getLong("sequence_no"),
                                rs.getTimestamp("recorded_at").toInstant(),
                                rs.getString("content_hash"),
                                rs.getString("previous_hash"),
                                rs.getString("record_hash")));
                    }
                    return Optional.empty();
                },
                clientId, idempotencyKey);
    }

    private ChainHead lockAndReadHead() {
        return jdbc.queryForObject(
                LOCK_HEAD_SQL,
                (rs, rowNum) -> new ChainHead(
                        rs.getLong("last_sequence_no"),
                        rs.getString("last_record_hash")));
    }

    private String toJsonString(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize payload to JSON", e);
        }
    }

    private record ChainHead(long lastSequenceNo, String lastRecordHash) {}

    private record IdempotencyRecord(
            String requestHash,
            UUID eventId,
            long sequenceNo,
            Instant recordedAt,
            String contentHash,
            String previousHash,
            String recordHash) {}
}
