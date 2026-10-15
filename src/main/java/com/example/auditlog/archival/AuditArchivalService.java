package com.example.auditlog.archival;

import com.example.auditlog.api.AuditEventNotFoundException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Application service for soft-archiving immutable audit events.
 *
 * <h2>Design invariant</h2>
 *
 * <p>Archival never modifies or removes {@code audit_event} rows. It inserts a metadata
 * record into {@code audit_event_archive} keyed by {@code event_id}. The original row
 * and all its hash columns remain intact, so {@code GET /audit/verify} continues to
 * verify archived events as part of the full unbroken chain.
 *
 * <h2>Idempotency</h2>
 *
 * <p>All archival operations use {@code ON CONFLICT (event_id) DO NOTHING}. Archiving the
 * same event twice is safe and returns the existing archive record on the second call.
 *
 * <h2>Failure handling</h2>
 *
 * <p>Single-event archival is fully atomic: either the archive row is committed or the
 * transaction rolls back with no side effects. Batch archival uses a single {@code INSERT
 * ... SELECT} statement; a mid-statement failure rolls back all-or-nothing, leaving the
 * table in a consistent state. Re-running archival is safe due to idempotency.
 */
@Service
public class AuditArchivalService {

    private static final Logger log = LoggerFactory.getLogger(AuditArchivalService.class);

    private static final String CHECK_EVENT_EXISTS_SQL =
            "SELECT count(*) FROM audit_event WHERE event_id = ?::uuid";

    private static final String INSERT_ARCHIVE_SQL =
            """
            INSERT INTO audit_event_archive (event_id, archived_at, policy_ref, archive_location)
            VALUES (?::uuid, ?, ?, '')
            ON CONFLICT (event_id) DO NOTHING
            """;

    private static final String SELECT_ARCHIVE_SQL =
            """
            SELECT event_id, archived_at, policy_ref, archive_location
            FROM audit_event_archive
            WHERE event_id = ?::uuid
            """;

    private static final String BATCH_ARCHIVE_SQL =
            """
            INSERT INTO audit_event_archive (event_id, archived_at, policy_ref, archive_location)
            SELECT event_id, ?, ?, ''
            FROM audit_event
            WHERE recorded_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM audit_event_archive arch WHERE arch.event_id = audit_event.event_id
              )
            ON CONFLICT (event_id) DO NOTHING
            """;

    private final JdbcTemplate jdbc;
    private final AuditRetentionProperties retentionProperties;
    private final Clock clock;
    private final org.springframework.core.env.Environment environment;

    public AuditArchivalService(
            JdbcTemplate jdbc,
            AuditRetentionProperties retentionProperties,
            Clock clock,
            org.springframework.core.env.Environment environment) {
        this.jdbc = jdbc;
        this.retentionProperties = retentionProperties;
        this.clock = clock;
        this.environment = environment;
    }

    @jakarta.annotation.PostConstruct
    public void validateRetentionConfiguration() {
        boolean isLocalOrTest = environment.acceptsProfiles(org.springframework.core.env.Profiles.of("local", "test"));
        Integer windowDays = retentionProperties.getWindowDays();
        if (!isLocalOrTest) {
            if (windowDays == null) {
                throw new IllegalStateException("Production startup failed: audit.retention.window-days is required outside local/test profiles.");
            }
            if (windowDays <= 0) {
                throw new IllegalStateException("Production startup failed: audit.retention.window-days must be a positive integer.");
            }
        } else {
            if (windowDays != null && windowDays <= 0) {
                throw new IllegalStateException("audit.retention.window-days must be a positive integer if provided.");
            }
        }
    }

    /**
     * Archives a single audit event by its UUID.
     *
     * <p>If the event is already archived, the existing archive record is returned without
     * error (idempotent). If the event does not exist in {@code audit_event}, an
     * {@link AuditEventNotFoundException} is thrown.
     *
     * @param eventId   the UUID of the event to archive
     * @param policyRef a non-blank label identifying the retention policy (e.g. {@code "manual"})
     * @return the archive record (either newly created or pre-existing)
     * @throws AuditEventNotFoundException if no event with the given UUID exists
     * @throws IllegalArgumentException    if {@code policyRef} is blank
     */
    @Transactional
    public ArchiveEventResult archive(UUID eventId, String policyRef) {
        if (!StringUtils.hasText(policyRef)) {
            throw new IllegalArgumentException("policyRef must not be blank");
        }

        Integer count = jdbc.queryForObject(CHECK_EVENT_EXISTS_SQL, Integer.class, eventId.toString());
        if (count == null || count == 0) {
            throw new AuditEventNotFoundException(eventId);
        }

        Instant now = clock.instant();
        jdbc.update(INSERT_ARCHIVE_SQL, eventId.toString(), Timestamp.from(now), policyRef);

        // Read back the committed row (either just-inserted or pre-existing via ON CONFLICT DO NOTHING)
        List<Map<String, Object>> rows = jdbc.queryForList(SELECT_ARCHIVE_SQL, eventId.toString());
        Map<String, Object> row = rows.get(0);

        UUID returnedId = (UUID) row.get("event_id");
        Instant archivedAt = ((Timestamp) row.get("archived_at")).toInstant();
        String returnedPolicyRef = (String) row.get("policy_ref");
        String archiveLocation = (String) row.get("archive_location");

        log.info("Audit event archived: eventId={} policyRef={}", eventId, returnedPolicyRef);
        return new ArchiveEventResult(returnedId, archivedAt, returnedPolicyRef, archiveLocation);
    }

    /**
     * Archives all audit events whose {@code recorded_at} is at or before the cutoff determined
     * by the configured retention window.
     *
     * <p>The cutoff is {@code now() - windowDays}. Already-archived events are skipped
     * (idempotent). The entire batch runs in a single atomic SQL statement; any failure
     * rolls back all-or-nothing.
     *
     * @param policyRef a non-blank label identifying the retention policy (e.g. {@code "default-90d"})
     * @return the number of events newly archived in this invocation
     * @throws IllegalArgumentException if {@code policyRef} is blank or the retention window is
     *                                  not configured or is not positive
     */
    @Transactional
    public int archiveEligible(String policyRef) {
        if (!StringUtils.hasText(policyRef)) {
            throw new IllegalArgumentException("policyRef must not be blank");
        }

        Integer windowDays = retentionProperties.getWindowDays();
        if (windowDays == null || windowDays <= 0) {
            throw new IllegalArgumentException(
                    "audit.retention.window-days must be configured as a positive integer");
        }

        Instant cutoff = clock.instant().minus(Duration.ofDays(windowDays));
        Instant now = clock.instant();

        int archived = jdbc.update(BATCH_ARCHIVE_SQL, Timestamp.from(now), policyRef, Timestamp.from(cutoff));

        log.info("Batch archival complete: policyRef={} windowDays={} cutoff={} archived={}",
                policyRef, windowDays, cutoff, archived);
        return archived;
    }
}
