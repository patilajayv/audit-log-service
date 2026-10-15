package com.example.auditlog.redaction;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Dedicated Spring-managed transactional collaborator for database persistence,
 * row-level locking, reconciliation, and state finalization during structured payload redaction.
 *
 * <p>Separating these operations into this collaborator guarantees that calls from
 * {@link AuditRedactionService} invoke the active Spring transaction proxy, ensuring atomic
 * database transactions, pessimistic row locking with {@code SELECT ... FOR UPDATE}, and
 * robust deduplication across multi-instance application nodes.
 */
@Component
public class AuditRedactionCoordinator {

    private static final Logger log = LoggerFactory.getLogger(AuditRedactionCoordinator.class);

    private static final String SELECT_COMPLETED_REDACTION_SQL =
            "SELECT redaction_id, operation_id, event_id, field_path, redacted_at, reason, "
            + "requested_by, redaction_type, status, key_id, meta_audit_sequence_no "
            + "FROM audit_event_redaction WHERE operation_id = ? AND status = 'COMPLETED'";

    private static final String INSERT_PENDING_REDACTION_SQL =
            """
            INSERT INTO audit_event_redaction (
                operation_id, event_id, field_path, reason, requested_by, redaction_type, status, key_id
            ) VALUES (?, ?::uuid, ?, ?, ?, ?, 'PENDING', ?)
            ON CONFLICT (operation_id) DO NOTHING
            """;

    private static final String LOCK_REDACTION_ROW_SQL =
            "SELECT redaction_id, operation_id, event_id, field_path, redacted_at, reason, "
            + "requested_by, redaction_type, status, key_id, meta_audit_sequence_no "
            + "FROM audit_event_redaction WHERE operation_id = ? FOR UPDATE";

    private static final String UPDATE_STATUS_SQL =
            "UPDATE audit_event_redaction SET status = ? WHERE operation_id = ?";

    private static final String UPDATE_COMPLETED_SQL =
            "UPDATE audit_event_redaction SET status = 'COMPLETED', meta_audit_sequence_no = ?, redacted_at = ? "
            + "WHERE operation_id = ?";

    private static final String FIND_DISCOVERED_META_EVENT_SQL =
            "SELECT sequence_no FROM audit_event WHERE event_type = 'PAYLOAD_REDACTED' "
            + "AND payload->>'redactionOperationId' = ? LIMIT 1";

    private final JdbcTemplate jdbc;
    private final AuditAppendService appendService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public AuditRedactionCoordinator(
            JdbcTemplate jdbc,
            AuditAppendService appendService,
            ObjectMapper objectMapper,
            Clock clock) {
        this.jdbc = jdbc;
        this.appendService = appendService;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    /**
     * Checks if a redaction operation has already reached COMPLETED status.
     */
    public Optional<RedactionResult> findCompleted(String operationId) {
        List<Map<String, Object>> rows = jdbc.queryForList(SELECT_COMPLETED_REDACTION_SQL, operationId);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(mapToResult(rows.get(0)));
    }

    /**
     * Ensures an initial PENDING record is registered in {@code audit_event_redaction}.
     */
    public void ensurePendingRegistered(
            String operationId,
            UUID eventId,
            String fieldPath,
            String reason,
            String requestedBy,
            String redactionType,
            String keyId) {
        try {
            jdbc.update(
                    INSERT_PENDING_REDACTION_SQL,
                    operationId,
                    eventId.toString(),
                    fieldPath,
                    reason,
                    requestedBy,
                    redactionType,
                    keyId);
        } catch (DuplicateKeyException ignored) {
            // Concurrently registered by another thread or node
        }
    }

    /**
     * Retrieves the current lifecycle status of a registered redaction operation.
     */
    public String getStatus(String operationId) {
        List<String> statuses = jdbc.query(
                "SELECT status FROM audit_event_redaction WHERE operation_id = ?",
                (rs, rowNum) -> rs.getString("status"),
                operationId);
        return statuses.isEmpty() ? null : statuses.get(0);
    }

    /**
     * Updates the status of an in-flight redaction operation.
     */
    public void updateStatus(String operationId, String newStatus) {
        jdbc.update(UPDATE_STATUS_SQL, newStatus, operationId);
    }

    /**
     * Atomically locks the redaction row with {@code SELECT ... FOR UPDATE}, discovers any pre-existing
     * meta-audit event, appends {@code PAYLOAD_REDACTED} if none exists, and finalizes the record as {@code COMPLETED}.
     *
     * <p>Because this method executes under an active Spring transaction boundary, the database row lock
     * is held continuously until commit, preventing concurrent appends and race conditions across multiple
     * application instances.
     *
     * @return the finalized redaction result
     */
    @Transactional
    public RedactionResult lockAndFinalizeMetaAudit(
            String operationId,
            UUID eventId,
            long targetSeq,
            String targetResourceType,
            String targetResourceId,
            String fieldPath,
            String reason,
            String requestedBy,
            String redactionType,
            String keyId) {

        // 1. Acquire exclusive row-level lock on audit_event_redaction
        List<Map<String, Object>> lockedRows = jdbc.queryForList(LOCK_REDACTION_ROW_SQL, operationId);
        if (lockedRows.isEmpty()) {
            throw new IllegalStateException("Redaction operation row not found for locking: " + operationId);
        }

        Map<String, Object> lockedRow = lockedRows.get(0);
        String currentStatus = (String) lockedRow.get("status");

        // If another transaction finished while we were waiting on the row lock, return immediately
        if ("COMPLETED".equals(currentStatus)) {
            log.info("Redaction operation already completed by competing transaction: operationId={}", operationId);
            return mapToResult(lockedRow);
        }

        // 2. Check if a PAYLOAD_REDACTED event was already appended to audit_event (reconciliation discovery)
        List<Long> discoveredSeqs = jdbc.query(
                FIND_DISCOVERED_META_EVENT_SQL,
                (rs, rowNum) -> rs.getLong("sequence_no"),
                operationId);

        long metaAuditSeq;
        if (!discoveredSeqs.isEmpty()) {
            metaAuditSeq = discoveredSeqs.get(0);
            log.info("Discovered pre-existing meta-audit event on chain: sequenceNo={} operationId={}",
                    metaAuditSeq, operationId);
        } else {
            // Build sanitized meta-audit payload (zero sensitive plaintext)
            ObjectNode metaPayload = objectMapper.createObjectNode();
            metaPayload.put("redactionOperationId", operationId);
            metaPayload.put("targetEventId", eventId.toString());
            metaPayload.put("targetSequenceNo", targetSeq);
            metaPayload.put("fieldPath", fieldPath);
            metaPayload.put("reason", reason);
            metaPayload.put("redactionType", redactionType);
            if (keyId != null) {
                metaPayload.put("keyId", keyId);
            }

            AppendEventRequest metaRequest = new AppendEventRequest(
                    "PAYLOAD_REDACTED",
                    requestedBy,
                    targetResourceType,
                    targetResourceId,
                    metaPayload,
                    clock.instant());

            try {
                AppendEventResult appendResult = appendService.append(metaRequest);
                metaAuditSeq = appendResult.sequenceNo();
                log.info("Appended PAYLOAD_REDACTED meta-event: sequenceNo={} operationId={}",
                        metaAuditSeq, operationId);
            } catch (DuplicateKeyException e) {
                // Secondary safeguard: caught unique index violation on idx_audit_event_meta_redaction_op
                log.info("Duplicate key detected on meta-event append; reconciling existing event: operationId={}", operationId);
                metaAuditSeq = jdbc.queryForObject(
                        FIND_DISCOVERED_META_EVENT_SQL,
                        Long.class,
                        operationId);
            }
        }

        // 3. Seal the redaction record as COMPLETED
        Instant completedAt = clock.instant();
        jdbc.update(UPDATE_COMPLETED_SQL, metaAuditSeq, Timestamp.from(completedAt), operationId);

        return new RedactionResult(
                eventId,
                fieldPath,
                completedAt,
                reason,
                requestedBy,
                redactionType,
                "COMPLETED",
                metaAuditSeq);
    }

    private RedactionResult mapToResult(Map<String, Object> row) {
        UUID eventId = (UUID) row.get("event_id");
        String fieldPath = (String) row.get("field_path");
        Timestamp redactedAtTs = (Timestamp) row.get("redacted_at");
        Instant redactedAt = redactedAtTs != null ? redactedAtTs.toInstant() : null;
        String reason = (String) row.get("reason");
        String requestedBy = (String) row.get("requested_by");
        String redactionType = (String) row.get("redaction_type");
        String status = (String) row.get("status");
        Long metaSeq = row.get("meta_audit_sequence_no") != null
                ? ((Number) row.get("meta_audit_sequence_no")).longValue()
                : null;

        return new RedactionResult(
                eventId, fieldPath, redactedAt, reason, requestedBy, redactionType, status, metaSeq);
    }
}
