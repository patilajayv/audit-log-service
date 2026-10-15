package com.example.auditlog.export;

import com.example.auditlog.api.PayloadTooLargeException;
import com.example.auditlog.hashing.AuditHashService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service orchestrating self-contained, independently verifiable bulk audit exports.
 *
 * <p>Enforces:
 * <ul>
 *   <li>Point-in-time database snapshot consistency under {@code REPEATABLE_READ} isolation.</li>
 *   <li>Configurable size boundaries bounding both total chain records and matched events (HTTP 413).</li>
 *   <li>Monotonic sequence ordering from genesis (sequence 1) to the observed chain head.</li>
 *   <li>Partitioning into full canonical events (for matched records) and privacy-preserving
 *       witness nodes (for unmatched intermediate records).</li>
 *   <li>Integration with Milestone 9 soft archival (populating {@code archivedAt} without mutating hashes).</li>
 *   <li>Integration with Milestone 10 structured redaction (identifying {@code CRYPTO_SHREDDED} vs.
 *       {@code MASKED} events, avoiding plaintext disclosure while preserving hash-chain commitments).</li>
 * </ul>
 */
@Service
public class AuditExportService {

    private static final Logger log = LoggerFactory.getLogger(AuditExportService.class);

    private static final String BUNDLE_VERSION = "1.0";

    private static final String SELECT_HEAD_SQL =
            "SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1";

    private static final String STREAM_ALL_EVENTS_UP_TO_HEAD_SQL = """
            SELECT ae.sequence_no, ae.event_id, ae.event_type, ae.actor_id, ae.resource_type, ae.resource_id,
                   ae.payload, ae.source_timestamp, ae.recorded_at, ae.canonicalization_version,
                   ae.content_hash, ae.previous_hash, ae.record_hash,
                   arch.archived_at
            FROM audit_event ae
            LEFT JOIN audit_event_archive arch ON arch.event_id = ae.event_id
            WHERE ae.sequence_no <= ?
            ORDER BY ae.sequence_no ASC
            """;

    private final JdbcTemplate jdbc;
    private final AuditHashService hashService;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final AuditExportProperties exportProperties;

    public AuditExportService(
            JdbcTemplate jdbc,
            AuditHashService hashService,
            ObjectMapper objectMapper,
            Clock clock,
            @Autowired(required = false) AuditExportProperties exportProperties) {
        this.jdbc = jdbc;
        this.hashService = hashService;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.exportProperties = exportProperties != null ? exportProperties : new AuditExportProperties();
    }

    /**
     * Generates a self-contained, verifiable export bundle for the specified criteria.
     *
     * @param criteria validated filter criteria
     * @return the complete {@link ExportBundleDto}
     * @throws PayloadTooLargeException if the requested export exceeds configured bounds
     */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ExportBundleDto exportBundle(ExportFilterCriteria criteria) {
        UUID exportId = UUID.randomUUID();
        Instant exportedAtInstant = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        String exportedAt = hashService.formatTimestamp(exportedAtInstant);

        // 1. Observe chain-head state for consistent snapshot
        List<Map<String, Object>> headRows = jdbc.queryForList(SELECT_HEAD_SQL);
        if (headRows.isEmpty()) {
            throw new IllegalStateException("audit_chain_head singleton row is missing");
        }

        Map<String, Object> headRow = headRows.get(0);
        long headSequenceNo = ((Number) headRow.get("last_sequence_no")).longValue();
        String headRecordHash = (String) headRow.get("last_record_hash");

        // Enforce total chain records upper limit
        if (headSequenceNo > exportProperties.getMaxTotalRecords()) {
            throw new PayloadTooLargeException(
                    "Export exceeds maximum supported total chain records limit of "
                            + exportProperties.getMaxTotalRecords() + " (requested chain head sequence: "
                            + headSequenceNo + "). Please refine criteria or export within bounded ranges.");
        }

        ExportFilterDto filterDto = new ExportFilterDto(
                criteria.filterType().name(),
                criteria.filterValue(),
                criteria.includeArchived());

        ExportChainHeadDto chainHeadDto = new ExportChainHeadDto(headSequenceNo, headRecordHash);

        if (headSequenceNo == 0L) {
            // Empty audit chain
            return new ExportBundleDto(
                    BUNDLE_VERSION,
                    exportId,
                    exportedAt,
                    filterDto,
                    chainHeadDto,
                    new ExportSummaryDto(0L, null, null, 0L),
                    Collections.emptyList(),
                    Collections.emptyList());
        }

        // 2. Stream all records up to headSequenceNo in sequence order
        List<ExportEventDto> matchedEvents = new ArrayList<>();
        List<ExportWitnessDto> witnesses = new ArrayList<>();

        jdbc.query(
                conn -> {
                    PreparedStatement ps = conn.prepareStatement(
                            STREAM_ALL_EVENTS_UP_TO_HEAD_SQL,
                            ResultSet.TYPE_FORWARD_ONLY,
                            ResultSet.CONCUR_READ_ONLY);
                    ps.setLong(1, headSequenceNo);
                    ps.setFetchSize(500);
                    return ps;
                },
                rs -> {
                    long seq = rs.getLong("sequence_no");
                    UUID eventId = (UUID) rs.getObject("event_id");
                    String eventType = rs.getString("event_type");
                    String actorId = rs.getString("actor_id");
                    String resourceType = rs.getString("resource_type");
                    String resourceId = rs.getString("resource_id");
                    String payloadJson = rs.getString("payload");
                    Timestamp sourceTimestamp = rs.getTimestamp("source_timestamp");
                    Timestamp recordedAt = rs.getTimestamp("recorded_at");
                    String canonicalVersion = rs.getString("canonicalization_version");
                    String contentHash = rs.getString("content_hash");
                    String previousHash = rs.getString("previous_hash");
                    String recordHash = rs.getString("record_hash");
                    Timestamp archivedAt = rs.getTimestamp("archived_at");

                    boolean matchesCriteria;
                    if (criteria.filterType() == ExportFilterCriteria.FilterType.ACTOR_ID) {
                        matchesCriteria = criteria.filterValue().equals(actorId);
                    } else {
                        matchesCriteria = criteria.filterValue().equals(resourceId)
                                && (criteria.requiredResourceType() == null || criteria.requiredResourceType().equals(resourceType));
                    }

                    // If archived records are excluded and this record is archived, treat it as non-matching
                    if (archivedAt != null && !criteria.includeArchived()) {
                        matchesCriteria = false;
                    }

                    if (matchesCriteria) {
                        // Enforce matched events upper limit
                        if (matchedEvents.size() >= exportProperties.getMaxMatchedEvents()) {
                            throw new PayloadTooLargeException(
                                    "Export exceeds maximum supported matching events limit of "
                                            + exportProperties.getMaxMatchedEvents() + ". Please refine your filter criteria.");
                        }

                        JsonNode payloadNode;
                        try {
                            payloadNode = objectMapper.readTree(payloadJson);
                        } catch (JsonProcessingException e) {
                            throw new IllegalStateException("Failed to parse stored payload JSON for sequence: " + seq, e);
                        }

                        String sourceTimestampStr = sourceTimestamp != null
                                ? hashService.formatTimestamp(sourceTimestamp.toInstant())
                                : null;
                        String recordedAtStr = recordedAt != null
                                ? hashService.formatTimestamp(recordedAt.toInstant())
                                : null;
                        String archivedAtStr = archivedAt != null
                                ? hashService.formatTimestamp(archivedAt.toInstant())
                                : null;

                        matchedEvents.add(new ExportEventDto(
                                seq,
                                eventId,
                                eventType,
                                actorId,
                                resourceType,
                                resourceId,
                                payloadNode,
                                sourceTimestampStr,
                                recordedAtStr,
                                canonicalVersion,
                                contentHash,
                                previousHash,
                                recordHash,
                                archivedAtStr,
                                null));
                    } else {
                        // Intermediate witness record: zero sensitive payloads, actors, or resources exposed
                        witnesses.add(new ExportWitnessDto(seq, previousHash, contentHash, recordHash));
                    }
                }
        );

        // 3. Apply redaction classification and projection masking
        List<ExportEventDto> finalMatchedEvents = applyRedactionMetadata(matchedEvents);

        // 4. Construct summary statistics
        Long firstMatchedSeq = finalMatchedEvents.isEmpty() ? null : finalMatchedEvents.get(0).sequenceNo();
        Long lastMatchedSeq = finalMatchedEvents.isEmpty() ? null : finalMatchedEvents.get(finalMatchedEvents.size() - 1).sequenceNo();

        ExportSummaryDto summaryDto = new ExportSummaryDto(
                finalMatchedEvents.size(),
                firstMatchedSeq,
                lastMatchedSeq,
                witnesses.size());

        return new ExportBundleDto(
                BUNDLE_VERSION,
                exportId,
                exportedAt,
                filterDto,
                chainHeadDto,
                summaryDto,
                finalMatchedEvents,
                witnesses);
    }

    private List<ExportEventDto> applyRedactionMetadata(List<ExportEventDto> events) {
        if (events.isEmpty()) {
            return events;
        }

        List<UUID> eventIds = events.stream().map(ExportEventDto::eventId).toList();
        String inPlaceholders = String.join(",", Collections.nCopies(eventIds.size(), "?::uuid"));
        String redactionSql = "SELECT event_id, field_path, redaction_type FROM audit_event_redaction "
                + "WHERE status = 'COMPLETED' AND event_id IN (" + inPlaceholders + ")";

        Map<UUID, List<String>> maskedPathsByEvent = new HashMap<>();
        Map<UUID, String> redactionTypeByEvent = new HashMap<>();

        jdbc.query(redactionSql, rs -> {
            UUID eid = (UUID) rs.getObject("event_id");
            String fp = rs.getString("field_path");
            String rType = rs.getString("redaction_type");
            redactionTypeByEvent.put(eid, rType);
            if ("MASKED".equalsIgnoreCase(rType)) {
                maskedPathsByEvent.computeIfAbsent(eid, k -> new ArrayList<>()).add(fp);
            }
        }, eventIds.stream().map(UUID::toString).toArray());

        if (redactionTypeByEvent.isEmpty()) {
            return events;
        }

        List<ExportEventDto> projected = new ArrayList<>(events.size());
        for (ExportEventDto event : events) {
            String rType = redactionTypeByEvent.get(event.eventId());
            if ("MASKED".equalsIgnoreCase(rType)) {
                List<String> paths = maskedPathsByEvent.get(event.eventId());
                JsonNode maskedPayload = (paths != null && !paths.isEmpty())
                        ? maskPayload(event.payload(), paths)
                        : event.payload();

                projected.add(new ExportEventDto(
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
                        event.archivedAt(),
                        "MASKED"));
            } else if ("CRYPTO_SHREDDED".equalsIgnoreCase(rType)) {
                // Ciphertext envelope preserved verbatim in payload
                projected.add(new ExportEventDto(
                        event.sequenceNo(),
                        event.eventId(),
                        event.eventType(),
                        event.actorId(),
                        event.resourceType(),
                        event.resourceId(),
                        event.payload(),
                        event.sourceTimestamp(),
                        event.recordedAt(),
                        event.canonicalizationVersion(),
                        event.contentHash(),
                        event.previousHash(),
                        event.recordHash(),
                        event.archivedAt(),
                        "CRYPTO_SHREDDED"));
            } else {
                projected.add(event);
            }
        }
        return projected;
    }

    private JsonNode maskPayload(JsonNode originalPayload, List<String> fieldPaths) {
        if (originalPayload == null || !originalPayload.isObject() || fieldPaths == null || fieldPaths.isEmpty()) {
            return originalPayload;
        }
        ObjectNode cloned = originalPayload.deepCopy();
        for (String fieldPath : fieldPaths) {
            String[] parts = fieldPath.split("\\.");
            JsonNode current = cloned;
            for (int i = 0; i < parts.length - 1; i++) {
                String part = parts[i];
                if (current == null || !current.isObject()) {
                    break;
                }
                current = current.get(part);
            }
            if (current instanceof ObjectNode objNode) {
                String leaf = parts[parts.length - 1];
                if (objNode.has(leaf)) {
                    objNode.put(leaf, "[REDACTED]");
                }
            }
        }
        return cloned;
    }
}
