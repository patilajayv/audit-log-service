package com.example.auditlog.compliance;

import com.example.auditlog.append.AppendEventRequest;
import com.example.auditlog.append.AppendEventResult;
import com.example.auditlog.append.AuditAppendService;
import com.example.auditlog.export.AuditExportService;
import com.example.auditlog.export.ExportBundleDto;
import com.example.auditlog.export.ExportFilterCriteria;
import com.example.auditlog.query.AuditEventDto;
import com.example.auditlog.query.AuditPageResponse;
import com.example.auditlog.query.AuditQueryCriteria;
import com.example.auditlog.query.AuditQueryService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Service orchestrating regulatory inquiries and constrained compliance exports for client account data.
 *
 * <p>Enforces fail-closed supervisory meta-auditing:
 * <ul>
 *   <li>Each query appends a durable {@code REGULATORY_AUDIT_ACCESSED} supervisory record.</li>
 *   <li>Each export appends a durable {@code REGULATORY_EXPORT_ACCESSED} supervisory record.</li>
 *   <li>If the supervisory append fails, execution terminates immediately and zero account data is returned.</li>
 *   <li>Supervisory records use {@code resourceType = 'COMPLIANCE_AUDIT'} and are cleanly excluded
 *       from account queries ({@code resourceType = 'ACCOUNT'}), preventing query feedback loops and pagination drift.</li>
 * </ul>
 */
@Service
public class AuditComplianceService {

    private static final Logger log = LoggerFactory.getLogger(AuditComplianceService.class);

    public static final String COMPLIANCE_RESOURCE_TYPE = "COMPLIANCE_AUDIT";
    public static final String ACCOUNT_RESOURCE_TYPE = "ACCOUNT";
    public static final String QUERY_EVENT_TYPE = "REGULATORY_AUDIT_ACCESSED";
    public static final String EXPORT_EVENT_TYPE = "REGULATORY_EXPORT_ACCESSED";

    private final AuditAppendService appendService;
    private final AuditQueryService queryService;
    private final AuditExportService exportService;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public AuditComplianceService(
            AuditAppendService appendService,
            AuditQueryService queryService,
            AuditExportService exportService,
            Clock clock) {
        this.appendService = appendService;
        this.queryService = queryService;
        this.exportService = exportService;
        this.objectMapper = new ObjectMapper();
        this.clock = clock;
    }

    /**
     * Executes a regulatory query for client account access events.
     *
     * <p>Enforces fail-closed supervisory auditing: the supervisory record is appended and committed
     * before the query is executed. If append fails, the query is never executed.
     *
     * @param accountId required client account identifier
     * @param actorId optional filter on accessor actor
     * @param eventType optional filter on access event type
     * @param from optional ISO-8601 UTC start time
     * @param to optional ISO-8601 UTC end time
     * @param page zero-based page index (defaults to 0)
     * @param size page size (defaults to 20, max 100)
     * @param includeArchived whether to include soft-archived events (defaults to true)
     * @param regulatorPrincipal authenticated examiner identity
     * @param correlationId request correlation ID
     * @return page of matching account access events
     */
    public AuditPageResponse<AuditEventDto> queryAccountAccess(
            String accountId,
            String actorId,
            String eventType,
            String from,
            String to,
            Integer page,
            Integer size,
            Boolean includeArchived,
            String regulatorPrincipal,
            String correlationId) {

        if (!StringUtils.hasText(accountId)) {
            throw new IllegalArgumentException("'accountId' is required and must not be blank");
        }

        boolean resolvedIncludeArchived = includeArchived == null || includeArchived;

        // 1. Durably append supervisory audit record in a dedicated write transaction (fail-closed)
        recordSupervisoryAudit(
                QUERY_EVENT_TYPE,
                accountId.trim(),
                regulatorPrincipal,
                correlationId,
                page,
                size,
                actorId,
                eventType,
                from,
                to,
                resolvedIncludeArchived);

        // 2. Execute read-only query constrained strictly to resourceType = "ACCOUNT" and resourceId = accountId
        AuditQueryCriteria criteria = AuditQueryCriteria.of(
                actorId,
                ACCOUNT_RESOURCE_TYPE,
                accountId.trim(),
                eventType,
                from,
                to,
                page,
                size,
                resolvedIncludeArchived);

        return queryService.query(criteria);
    }

    /**
     * Exports a self-contained, independently verifiable bundle strictly constrained to client account data.
     *
     * <p>Enforces fail-closed supervisory auditing: the supervisory record is appended and committed
     * before the export bundle snapshot is captured.
     *
     * @param accountId required client account identifier
     * @param includeArchived whether to include soft-archived events (defaults to true)
     * @param regulatorPrincipal authenticated examiner identity
     * @param correlationId request correlation ID
     * @return self-contained verifiable export bundle
     */
    public ExportBundleDto exportAccountAccess(
            String accountId,
            Boolean includeArchived,
            String regulatorPrincipal,
            String correlationId) {

        if (!StringUtils.hasText(accountId)) {
            throw new IllegalArgumentException("'accountId' is required and must not be blank");
        }

        boolean resolvedIncludeArchived = includeArchived == null || includeArchived;

        // 1. Durably append supervisory export record in a dedicated write transaction (fail-closed)
        recordSupervisoryExport(
                accountId.trim(),
                regulatorPrincipal,
                correlationId,
                resolvedIncludeArchived);

        // 2. Generate constrained export bundle
        ExportFilterCriteria criteria = ExportFilterCriteria.forAccount(accountId.trim(), resolvedIncludeArchived);
        return exportService.exportBundle(criteria);
    }

    private void recordSupervisoryAudit(
            String eventType,
            String accountId,
            String regulatorPrincipal,
            String correlationId,
            Integer page,
            Integer size,
            String filterActorId,
            String filterEventType,
            String from,
            String to,
            boolean includeArchived) {

        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("action", "QUERY_ACCOUNT_ACCESS");
        payload.put("targetAccountId", accountId);
        payload.put("correlationId", correlationId != null ? correlationId : "");
        if (page != null) {
            payload.put("page", page);
        }
        if (size != null) {
            payload.put("size", size);
        }
        payload.put("includeArchived", includeArchived);

        ObjectNode filters = payload.putObject("filters");
        if (filterActorId != null) {
            filters.put("actorId", filterActorId);
        }
        if (filterEventType != null) {
            filters.put("eventType", filterEventType);
        }
        if (from != null) {
            filters.put("from", from);
        }
        if (to != null) {
            filters.put("to", to);
        }

        AppendEventRequest request = new AppendEventRequest(
                eventType,
                regulatorPrincipal != null ? regulatorPrincipal : "anonymous",
                COMPLIANCE_RESOURCE_TYPE,
                accountId,
                payload,
                null);

        AppendEventResult result = appendService.append(request);
        log.info("Committed supervisory audit event: eventId={}, seq={}, targetAccount={}",
                result.eventId(), result.sequenceNo(), accountId);
    }

    private void recordSupervisoryExport(
            String accountId,
            String regulatorPrincipal,
            String correlationId,
            boolean includeArchived) {

        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("action", "EXPORT_ACCOUNT_ACCESS");
        payload.put("targetAccountId", accountId);
        payload.put("correlationId", correlationId != null ? correlationId : "");
        payload.put("includeArchived", includeArchived);

        AppendEventRequest request = new AppendEventRequest(
                EXPORT_EVENT_TYPE,
                regulatorPrincipal != null ? regulatorPrincipal : "anonymous",
                COMPLIANCE_RESOURCE_TYPE,
                accountId,
                payload,
                null);

        AppendEventResult result = appendService.append(request);
        log.info("Committed supervisory export event: eventId={}, seq={}, targetAccount={}",
                result.eventId(), result.sequenceNo(), accountId);
    }
}
