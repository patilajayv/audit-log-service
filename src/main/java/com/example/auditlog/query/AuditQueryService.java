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
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read-only application service for searching and paginating immutable audit events.
 *
 * <p>Enforces strictly parameterized SQL queries for all user criteria, applies stable
 * {@code sequence_no ASC} ordering, and never mutates audit records or the chain head.
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
            conditions.add("actor_id = ?");
            params.add(criteria.actorId());
        }
        if (criteria.resourceType() != null) {
            conditions.add("resource_type = ?");
            params.add(criteria.resourceType());
        }
        if (criteria.resourceId() != null) {
            conditions.add("resource_id = ?");
            params.add(criteria.resourceId());
        }
        if (criteria.eventType() != null) {
            conditions.add("event_type = ?");
            params.add(criteria.eventType());
        }
        if (criteria.from() != null) {
            conditions.add("recorded_at >= ?");
            params.add(Timestamp.from(criteria.from()));
        }
        if (criteria.to() != null) {
            conditions.add("recorded_at <= ?");
            params.add(Timestamp.from(criteria.to()));
        }

        String whereClause = conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions);

        // Count total matching elements
        String countSql = "SELECT count(*) FROM audit_event" + whereClause;
        Long countResult = jdbc.queryForObject(countSql, Long.class, params.toArray());
        long totalElements = countResult != null ? countResult : 0L;

        if (totalElements == 0) {
            return AuditPageResponse.of(Collections.emptyList(), criteria.page(), criteria.size(), 0L);
        }

        long offset = (long) criteria.page() * criteria.size();
        if (offset >= totalElements) {
            return AuditPageResponse.of(Collections.emptyList(), criteria.page(), criteria.size(), totalElements);
        }

        // Fetch paginated data ordered strictly by sequence_no ASC
        String dataSql = """
                SELECT sequence_no, event_id, event_type, actor_id, resource_type, resource_id,
                       payload, source_timestamp, recorded_at, canonicalization_version,
                       content_hash, previous_hash, record_hash
                FROM audit_event
                """ + whereClause + " ORDER BY sequence_no ASC LIMIT ? OFFSET ?";

        List<Object> dataParams = new ArrayList<>(params);
        dataParams.add(criteria.size());
        dataParams.add(offset);

        List<AuditEventDto> events = jdbc.query(dataSql, new AuditEventRowMapper(), dataParams.toArray());

        return AuditPageResponse.of(events, criteria.page(), criteria.size(), totalElements);
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
                    recordHash);
        }
    }
}
