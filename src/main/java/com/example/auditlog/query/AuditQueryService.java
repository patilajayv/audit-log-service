package com.example.auditlog.query;

import com.example.auditlog.hashing.AuditHashService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read-only application service for searching and paginating immutable audit events.
 *
 * <p>Enforces strictly parameterized SQL queries for all user criteria, applies stable
 * {@code sequence_no ASC} ordering, and never mutates audit records or the chain head.
 *
 * <p>When {@code criteria.includeArchived()} is {@code false} (the default), both the count
 * query and the data query exclude events that have a row in {@code audit_event_archive}.
 * When {@code true}, all events are returned and the {@link AuditEventDto#archivedAt()} field
 * is populated for archived events (null for non-archived events).
 *
 * <p>For events with completed redactions in {@code audit_event_redaction}, redacted field paths
 * are masked with {@code "[REDACTED]"} in the returned payload projection without altering
 * original database records or cryptographic hash commitments.
 */
@Service
@Transactional(readOnly = true)
public class AuditQueryService {

    private final JdbcTemplate jdbc;
    private final AuditHashService hashService;
    private final ObjectMapper objectMapper;

    public AuditQueryService(JdbcTemplate jdbc, AuditHashService hashService) {
        this.jdbc = jdbc;
        this.hashService = hashService;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Executes a filtered, paginated query against the audit event log.
     *
     * @param criteria validated search filters and pagination bounds
     * @return a page response containing matched audit events and pagination metadata
     */
    public AuditPageResponse<AuditEventDto> query(AuditQueryCriteria criteria) {
        List<String> conditions = new ArrayList<>();
        List<Object> params = new ArrayList<>();

        if (criteria.actorId() != null) {
            conditions.add("ae.actor_id = ?");
            params.add(criteria.actorId());
        }
        if (criteria.resourceType() != null) {
            conditions.add("ae.resource_type = ?");
            params.add(criteria.resourceType());
        }
        if (criteria.resourceId() != null) {
            conditions.add("ae.resource_id = ?");
            params.add(criteria.resourceId());
        }
        if (criteria.eventType() != null) {
            conditions.add("ae.event_type = ?");
            params.add(criteria.eventType());
        }
        if (criteria.from() != null) {
            conditions.add("ae.recorded_at >= ?");
            params.add(Timestamp.from(criteria.from()));
        }
        if (criteria.to() != null) {
            conditions.add("ae.recorded_at <= ?");
            params.add(Timestamp.from(criteria.to()));
        }

        // Exclude archived events unless the caller explicitly requests them
        if (!criteria.includeArchived()) {
            conditions.add("NOT EXISTS (SELECT 1 FROM audit_event_archive arch WHERE arch.event_id = ae.event_id)");
        }

        String whereClause = conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions);

        // Count total matching elements (using the same alias and conditions)
        String countSql = "SELECT count(*) FROM audit_event ae" + whereClause;
        Long countResult = jdbc.queryForObject(countSql, Long.class, params.toArray());
        long totalElements = countResult != null ? countResult : 0L;

        if (totalElements == 0) {
            return AuditPageResponse.of(Collections.emptyList(), criteria.page(), criteria.size(), 0L);
        }

        long offset = (long) criteria.page() * criteria.size();
        if (offset >= totalElements) {
            return AuditPageResponse.of(Collections.emptyList(), criteria.page(), criteria.size(), totalElements);
        }

        // Fetch paginated data ordered strictly by sequence_no ASC.
        // LEFT JOIN audit_event_archive to surface archivedAt (null when not archived).
        String dataSql = """
                SELECT ae.sequence_no, ae.event_id, ae.event_type, ae.actor_id,
                       ae.resource_type, ae.resource_id,
                       ae.payload, ae.source_timestamp, ae.recorded_at,
                       ae.canonicalization_version,
                       ae.content_hash, ae.previous_hash, ae.record_hash,
                       arch.archived_at
                FROM audit_event ae
                LEFT JOIN audit_event_archive arch ON arch.event_id = ae.event_id
                """ + whereClause + " ORDER BY ae.sequence_no ASC LIMIT ? OFFSET ?";

        List<Object> dataParams = new ArrayList<>(params);
        dataParams.add(criteria.size());
        dataParams.add(offset);

        List<AuditEventDto> events = jdbc.query(dataSql, new AuditEventRowMapper(), dataParams.toArray());

        if (events.isEmpty()) {
            return AuditPageResponse.of(events, criteria.page(), criteria.size(), totalElements);
        }

        // Apply read-time redaction masking for any completed redactions
        List<UUID> eventIds = events.stream().map(AuditEventDto::eventId).toList();
        String inPlaceholders = String.join(",", Collections.nCopies(eventIds.size(), "?::uuid"));
        String redactionSql = "SELECT event_id, field_path FROM audit_event_redaction "
                + "WHERE status = 'COMPLETED' AND event_id IN (" + inPlaceholders + ")";

        Map<UUID, List<String>> redactionsByEvent = new HashMap<>();
        jdbc.query(redactionSql, rs -> {
            UUID eid = (UUID) rs.getObject("event_id");
            String fp = rs.getString("field_path");
            redactionsByEvent.computeIfAbsent(eid, k -> new ArrayList<>()).add(fp);
        }, eventIds.stream().map(UUID::toString).toArray());

        if (redactionsByEvent.isEmpty()) {
            return AuditPageResponse.of(events, criteria.page(), criteria.size(), totalElements);
        }

        List<AuditEventDto> projectedEvents = new ArrayList<>(events.size());
        for (AuditEventDto event : events) {
            List<String> redactedPaths = redactionsByEvent.get(event.eventId());
            if (redactedPaths != null && !redactedPaths.isEmpty()) {
                JsonNode maskedPayload = maskPayload(event.payload(), redactedPaths);
                projectedEvents.add(new AuditEventDto(
                        event.sequenceNo(),
                        event.eventId(),
                        event.eventType(),
                        event.actorId(),
                        event.resourceType(),
                        event.resourceId(),
                        maskedPayload,
                        event.sourceTimestamp(),
                        event.recordedAt(),
                        event.canonicalizationVersion(),
                        event.contentHash(),
                        event.previousHash(),
                        event.recordHash(),
                        event.archivedAt()));
            } else {
                projectedEvents.add(event);
            }
        }

        return AuditPageResponse.of(projectedEvents, criteria.page(), criteria.size(), totalElements);
    }

    private JsonNode maskPayload(JsonNode originalPayload, List<String> fieldPaths) {
        if (originalPayload == null || !originalPayload.isObject() || fieldPaths == null || fieldPaths.isEmpty()) {
            return originalPayload;
        }
        ObjectNode cloned = originalPayload.deepCopy();
        for (String fieldPath : fieldPaths) {
            maskFieldPath(cloned, fieldPath);
        }
        return cloned;
    }

    private void maskFieldPath(ObjectNode root, String fieldPath) {
        String[] parts = fieldPath.split("\\.");
        JsonNode current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            if (current == null || !current.isObject()) {
                return;
            }
            current = current.get(part);
        }
        if (current instanceof ObjectNode objectNode) {
            String leaf = parts[parts.length - 1];
            if (objectNode.has(leaf)) {
                objectNode.put(leaf, "[REDACTED]");
            }
        }
    }

    private class AuditEventRowMapper implements RowMapper<AuditEventDto> {
        @Override
        public AuditEventDto mapRow(ResultSet rs, int rowNum) throws SQLException {
            long sequenceNo = rs.getLong("sequence_no");
            UUID eventId = (UUID) rs.getObject("event_id");
            String eventType = rs.getString("event_type");
            String actorId = rs.getString("actor_id");
            String resourceType = rs.getString("resource_type");
            String resourceId = rs.getString("resource_id");

            String payloadJson = rs.getString("payload");
            JsonNode payloadNode;
            try {
                payloadNode = objectMapper.readTree(payloadJson);
            } catch (JsonProcessingException e) {
                throw new SQLException("Failed to deserialize audit event payload JSON", e);
            }

            Timestamp sourceTs = rs.getTimestamp("source_timestamp");
            String formattedSourceTs = sourceTs != null ? hashService.formatTimestamp(sourceTs.toInstant()) : null;

            Timestamp recordedAtTs = rs.getTimestamp("recorded_at");
            String formattedRecordedAt = hashService.formatTimestamp(recordedAtTs.toInstant());

            String canonicalizationVersion = rs.getString("canonicalization_version");
            String contentHash = rs.getString("content_hash");
            String previousHash = rs.getString("previous_hash");
            String recordHash = rs.getString("record_hash");

            Timestamp archivedAtTs = rs.getTimestamp("archived_at");
            String formattedArchivedAt = archivedAtTs != null
                    ? hashService.formatTimestamp(archivedAtTs.toInstant())
                    : null;

            return new AuditEventDto(
                    sequenceNo,
                    eventId,
                    eventType,
                    actorId,
                    resourceType,
                    resourceId,
                    payloadNode,
                    formattedSourceTs,
                    formattedRecordedAt,
                    canonicalizationVersion,
                    contentHash,
                    previousHash,
                    recordHash,
                    formattedArchivedAt);
        }
    }
}
