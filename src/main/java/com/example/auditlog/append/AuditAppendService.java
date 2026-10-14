package com.example.auditlog.append;

import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.hashing.CanonicalEventContent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application service that appends a validated audit event to the hash chain.
 *
 * <h2>Transactional protocol</h2>
 *
 * <p>All five steps execute in a single database transaction:
 *
 * <ol>
 *   <li>Lock the singleton chain-head row with {@code SELECT ... FOR UPDATE}.
 *   <li>Derive the next sequence number and {@code previous_hash} from the locked head.
 *   <li>Canonicalize and hash the event ({@code content_hash} and {@code record_hash}).
 *   <li>Insert the new event row.
 *   <li>Advance the chain-head row to the new sequence number and {@code record_hash}.
 * </ol>
 *
 * <p>The head-row lock serializes concurrent writers. Any failure in steps 3–5 causes a full
 * rollback, leaving the chain unchanged. The database triggers installed by the V2 migration
 * provide defense-in-depth for the same ordering invariants.
 *
 * <h2>Concurrency</h2>
 *
 * <p>Because writers acquire an exclusive row lock on the single chain-head row, only one
 * append can proceed at a time. A concurrent transaction attempting to lock the same row
 * will block and, if a {@code lock_timeout} is set, will receive a {@code 55P03} error.
 * This naturally prevents duplicate or skipped sequence numbers; no optimistic-concurrency
 * retry is required or appropriate here.
 *
 * <h2>Retries</h2>
 *
 * <p>This service does not retry internally. Lock contention ({@code 55P03}) and serialization
 * failures are propagated to the caller; the transaction boundary is managed by the caller or
 * the Spring {@code @Transactional} interceptor. Retrying inside a failed transaction is unsafe.
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
     * Validates and appends an audit event to the chain in a single atomic transaction.
     *
     * <p>Validation of required fields is enforced by the {@link AppendEventRequest} constructor.
     * Database-level constraints and triggers provide defense-in-depth.
     *
     * @param request the event to append; validation is enforced by the record constructor
     * @return the committed event's identity, chain position, and hashes
     * @throws DataAccessException if the database operation fails (including lock timeout,
     *                             constraint violation, or trigger rejection)
     */
    @Transactional
    public AppendEventResult append(AppendEventRequest request) {
        // 1. Lock the chain-head row with FOR UPDATE to serialize concurrent appends.
        //    Both sequence number and previous hash are read in a single round-trip.
        ChainHead head = lockAndReadHead();
        long nextSequenceNo = head.lastSequenceNo() + 1;
        String previousHash = head.lastRecordHash();

        // 2. Assign service-side identity and timestamp (truncated to milliseconds).
        UUID eventId = UUID.randomUUID();
        Instant recordedAt = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        Instant sourceTimestamp = request.sourceTimestamp() != null
                ? request.sourceTimestamp().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)
                : null;

        // 3. Canonicalize and hash the event.
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

        // 4. Insert the event row.
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

        // 5. Advance the chain-head row.
        jdbc.update(ADVANCE_HEAD_SQL, nextSequenceNo, recordHash);

        return new AppendEventResult(eventId, nextSequenceNo, recordedAt, contentHash, previousHash, recordHash);
    }

    /**
     * Acquires an exclusive row lock on the chain-head row and reads both {@code last_sequence_no}
     * and {@code last_record_hash} in a single SQL round-trip.
     *
     * <p>Must be called within an active transaction so that the lock is held until commit.
     */
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

    /** Snapshot of the chain-head state read at lock time. */
    private record ChainHead(long lastSequenceNo, String lastRecordHash) {}
}
