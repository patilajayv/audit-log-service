package com.example.auditlog.redaction;

import com.example.auditlog.api.AuditEventNotFoundException;
import com.example.auditlog.crypto.KeyManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating structured payload redaction across key lifecycle management,
 * metadata persistence, and immutable meta-auditing.
 *
 * <h2>Execution Guarantees</h2>
 * <ul>
 *   <li><strong>Ledger Immutability:</strong> Original {@code audit_event} records, sequence numbers,
 *       and cryptographic hashes are NEVER modified or deleted.</li>
 *   <li><strong>Zero Plaintext in Meta-Audit:</strong> The appended {@code PAYLOAD_REDACTED} event
 *       records only coordinate metadata, never sensitive plaintext values.</li>
 *   <li><strong>Reconciliation on Retry:</strong> Before appending a meta-event, queries the ledger
 *       to discover if a matching {@code redactionOperationId} was already appended in an earlier
 *       interrupted run, guaranteeing exactly-once logical meta-auditing without duplicates.</li>
 *   <li><strong>Multi-Instance Concurrency:</strong> Delegates transactional state finalization to
 *       {@link AuditRedactionCoordinator}, which acquires a pessimistic row lock
 *       ({@code SELECT ... FOR UPDATE}) to serialize competing requests across distributed nodes.</li>
 * </ul>
 */
@Service
public class AuditRedactionService {

    private static final Logger log = LoggerFactory.getLogger(AuditRedactionService.class);

    private static final String SELECT_TARGET_EVENT_SQL =
            "SELECT sequence_no, event_type, actor_id, resource_type, resource_id, payload "
            + "FROM audit_event WHERE event_id = ?::uuid";

    private final JdbcTemplate jdbc;
    private final AuditRedactionCoordinator coordinator;
    private final KeyManager keyManager;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, Object> operationLocks = new ConcurrentHashMap<>();

    public AuditRedactionService(
            JdbcTemplate jdbc,
            AuditRedactionCoordinator coordinator,
            KeyManager keyManager,
            ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.coordinator = coordinator;
        this.keyManager = keyManager;
        this.objectMapper = objectMapper;
    }

    /**
     * Executes structured redaction of a payload field for the specified event.
     *
     * @param eventId the target event UUID
     * @param request the validated redaction parameters
     * @return the completed redaction result
     * @throws AuditEventNotFoundException       if eventId does not exist
     * @throws IllegalArgumentException          if fieldPath does not exist in the payload
     * @throws RedactionKeyDestructionException  if key destruction in KeyManager fails
     */
    public RedactionResult redact(UUID eventId, RedactionRequest request) {
        String fieldPath = request.fieldPath();
        String operationId = "redact:" + eventId + ":" + fieldPath;

        Object lock = operationLocks.computeIfAbsent(operationId, k -> new Object());
        synchronized (lock) {
            try {
                return executeRedaction(eventId, request, fieldPath, operationId);
            } finally {
                operationLocks.remove(operationId, lock);
            }
        }
    }

    private RedactionResult executeRedaction(
            UUID eventId, RedactionRequest request, String fieldPath, String operationId) {
        // 1. Check if already completed (idempotency fast-path)
        Optional<RedactionResult> completedOpt = coordinator.findCompleted(operationId);
        if (completedOpt.isPresent()) {
            log.info("Redaction already completed: operationId={}", operationId);
            return completedOpt.get();
        }

        // 2. Fetch and inspect target audit event
        List<Map<String, Object>> targetRows = jdbc.queryForList(SELECT_TARGET_EVENT_SQL, eventId.toString());
        if (targetRows.isEmpty()) {
            throw new AuditEventNotFoundException(eventId);
        }
        Map<String, Object> targetRow = targetRows.get(0);
        long targetSeq = ((Number) targetRow.get("sequence_no")).longValue();
        String targetResourceType = (String) targetRow.get("resource_type");
        String targetResourceId = (String) targetRow.get("resource_id");
        Object payloadObj = targetRow.get("payload");
        String payloadJson = payloadObj != null ? payloadObj.toString() : "{}";

        JsonNode payloadNode;
        try {
            payloadNode = objectMapper.readTree(payloadJson);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse stored payload JSON for event: " + eventId, e);
        }

        JsonNode targetFieldNode = resolveFieldNode(payloadNode, fieldPath);
        if (targetFieldNode == null || targetFieldNode.isMissingNode()) {
            throw new IllegalArgumentException("Field path '" + fieldPath + "' not found in event payload");
        }

        // 3. Determine redaction category: EncryptedEnvelope vs. Legacy Plaintext
        boolean isEnvelope = targetFieldNode.isObject()
                && "EncryptedEnvelope".equals(targetFieldNode.path("@type").asText())
                && targetFieldNode.hasNonNull("keyId");

        String redactionType = isEnvelope ? "CRYPTO_SHREDDED" : "MASKED";
        String keyId = isEnvelope ? targetFieldNode.path("keyId").asText() : null;

        // 4. Ensure PENDING record is registered in audit_event_redaction
        coordinator.ensurePendingRegistered(
                operationId,
                eventId,
                fieldPath,
                request.reason(),
                request.requestedBy(),
                redactionType,
                keyId);

        String currentStatus = coordinator.getStatus(operationId);
        if ("COMPLETED".equals(currentStatus)) {
            return coordinator.findCompleted(operationId).orElseThrow();
        }

        // 5. If envelope, execute key destruction in KeyManager (if not already destroyed)
        if (!"KEY_DESTROYED".equals(currentStatus)) {
            if (isEnvelope && keyId != null) {
                try {
                    keyManager.destroyKey(keyId);
                    coordinator.updateStatus(operationId, "KEY_DESTROYED");
                } catch (Exception e) {
                    coordinator.updateStatus(operationId, "KEY_DESTRUCTION_FAILED");
                    throw new RedactionKeyDestructionException(keyId, e);
                }
            } else {
                // Legacy plaintext transitions directly
                coordinator.updateStatus(operationId, "KEY_DESTROYED");
            }
        }

        // 6. Finalize in atomic database transaction with pessimistic row locking and reconciliation
        return coordinator.lockAndFinalizeMetaAudit(
                operationId,
                eventId,
                targetSeq,
                targetResourceType,
                targetResourceId,
                fieldPath,
                request.reason(),
                request.requestedBy(),
                redactionType,
                keyId);
    }

    private JsonNode resolveFieldNode(JsonNode root, String fieldPath) {
        if (root == null || !root.isObject()) {
            return null;
        }
        String[] parts = fieldPath.split("\\.");
        JsonNode current = root;
        for (String part : parts) {
            if (current == null || !current.isObject()) {
                return null;
            }
            current = current.get(part);
        }
        return current;
    }
}
