# Requirements and Decisions

## Status and terminology

This document separates assignment requirements from engineering choices. "Requirement" means the assessment explicitly asks for it. "Assumption" fills in missing product detail. "Recommendation" is the current implementation choice and can change with recorded rationale.

## Scenario A: Core Audit Log Service

### Requirements

- Provide a write API that accepts `eventType`, `actorId`, `resourceType`, `resourceId`, structured `payload`, and an event timestamp.
- Keep records append-only. The API must not expose update or delete operations.
- Provide a query API that filters by any combination of actor, resource type and ID, event type, and time range. Support pagination.
- Store a content hash and previous-record hash for every event, using a defined genesis value for the first event.
- Provide `GET /audit/verify`, which reports whether the complete chain is intact and, when broken, identifies the first inconsistency and violation type.
- Demonstrate tamper detection by modifying a stored record directly and verifying again.

### Assumptions

- `recorded_at` is service-assigned UTC time. `source_timestamp` is optional caller context and is not treated as an authoritative clock.

### Recommendations

- A single global chain is sufficient for the prototype. Its sequence defines the authoritative audit order.
- The service returns stable sequence-order pagination. Timestamp order is a query concern, not chain order.
- Canonical JSON follows RFC 8785 (JCS) via `java-json-canonicalization:1.1`. The canonical object covers nine fields: `actorId`, `canonicalizationVersion` (`JCS-1`), `eventId`, `eventType`, `payload`, `recordedAt`, `resourceId`, `resourceType`, and `sourceTimestamp`.
- Numeric limits follow RFC 8785 Appendix D and RFC 7493 (I-JSON §2.2): Integers in the safe IEEE-754 range [-(2^53 - 1), 2^53 - 1] serialize as numbers; integers outside this range and non-finite floats are actively rejected. Exact 64-bit or arbitrary-precision values must be encoded as JSON strings. Duplicate object keys are rejected.
- Timestamps (`recordedAt` and optional `sourceTimestamp`) are normalized to UTC milliseconds (`ChronoUnit.MILLIS`) upon assignment/ingestion.
- `record_hash` uses 4-byte big-endian length-prefixed domain separation over `AUDIT_RECORD_V1`, decimal sequence, previous hash, and content hash to prevent field-boundary ambiguity.
- Request-body size is strictly limited to 1 MiB (1,048,576 bytes) via servlet filter on both declared-length and chunked/streaming requests, returning HTTP 413 before deserialization.
- Strict duplicate-key detection is enforced globally across root request properties and nested payload objects (RFC 8785 §3.2.3), returning HTTP 400.
- Handled errors return sanitized responses without disclosing SQL syntax, table names, constraint details, or stack traces, while unexpected exceptions receive a generic HTTP 500 response. Transient lock contention (SQLState `55P03`) returns HTTP 503 with `Retry-After: 1`.
- Operational logging omits `actorId`, `resourceId`, and event `payload`; requests are traced via correlation IDs.
- Query API (`GET /audit/events`) uses 100% parameterized SQL for all filter criteria (`actorId`, `resourceType`, `resourceId`, `eventType`, `from`, `to`), applying identical filters to both count and data queries.
- Time range filtering operates on service-assigned `recorded_at` using ISO-8601 UTC timestamps, with inclusive bounds `[from, to]`.
- Pagination enforces validated bounds (`page >= 0`, `1 <= size <= 100`) and deterministic ordering by `sequence_no ASC`. Separate requests under PostgreSQL `READ COMMITTED` isolation do not share a transaction snapshot across pages, but already-committed records are deterministically ordered.
- Query validation rejects blank filters, negative page numbers, invalid sizes, malformed timestamps, or `from > to` with sanitized HTTP 400 responses.
- Queries execute under read-only transactions (`@Transactional(readOnly = true)`) and never mutate stored rows, sequence numbers, or the chain head.
- Verification API (`GET /audit/verify`) executes in `@Transactional(readOnly = true)` using cursor-based streaming (`fetchSize = 500`) to avoid loading large datasets into memory, stopping immediately at the first inconsistency.
- Verification response cleanly separates declared chain-head metadata from verified values (`recordsVerified`, `headSequenceNo`, `headRecordHash`, `lastVerifiedSequenceNo`, `lastVerifiedRecordHash`, `violation`).
- Missing or malformed singleton `audit_chain_head` row is reported as a structured `CHAIN_HEAD_MISMATCH` inconsistency rather than a generic database exception.
- Verification detects corruption and tampering relative to the local stored chain and head; detecting complete history rewriting by a superuser requires an external trusted anchor.
- Stateless HTTP Basic authentication with BCrypt password hashing enforces least-privilege role separation: `POST /audit/events` requires `AUDIT_WRITER`, `GET /audit/events` requires `AUDITOR`, and `GET /audit/verify` requires `AUDITOR`. All unmapped routes are denied by default (`.anyRequest().denyAll()`).
- Unauthenticated requests receive sanitized HTTP 401 `ErrorResponse` with standard `WWW-Authenticate: Basic realm="AuditLogService"` header. Insufficiently privileged requests receive sanitized HTTP 403 `ErrorResponse` without `WWW-Authenticate`.
- External credential sourcing via environment variables (`AUDIT_SECURITY_WRITER_USERNAME`, `AUDIT_SECURITY_WRITER_PASSWORD`, etc.) with fail-fast startup validation in production mode rejecting empty, short (< 8 chars), or insecure placeholder defaults (`password`, `changeme`, `secret`, `admin`, `writer-secret`, `auditor-secret`, etc.).
- Safe development defaults isolated to `application-local.yaml` under `local` profile, and dedicated test credentials in `src/test/resources/application.yaml`.
- 401 and 403 rejections are intercepted at filter layer before execution, guaranteeing database records and chain-head state remain strictly unmodified.

### Acceptance criteria

- A valid event is appended via `POST /audit/events`, returning `201 Created` with monotonic sequence, assigned UUID, hashes, and previous hash.
- Oversized (> 1 MiB), duplicate-key, or malformed requests are rejected without inserting rows or advancing the chain head.
- All documented filter combinations return the expected stable pages ordered deterministically by `sequence_no ASC`.
- Query and verification execution are strictly read-only and leave row counts, sequence numbers, and `audit_chain_head` unaltered.
- Invalid query parameters return sanitized HTTP 400 responses without disclosing internal errors or stack traces.
- `GET /audit/verify` returns `200 OK` with `status: "INTACT"` for empty and valid chains.
- Direct modifications to stored payloads, content hashes, genesis hash, previous-hash links, record hashes, deleted events (first, middle, trailing), or altered chain-head state cause `/audit/verify` to return `200 OK` with `status: "CORRUPTED"` and the exact violation type and sequence.
- Unauthenticated requests to any endpoint return HTTP 401 with `WWW-Authenticate: Basic realm="AuditLogService"` and sanitized `ErrorResponse`.
- Invalid credentials return HTTP 401 with `WWW-Authenticate` header.
- `AUDITOR` callers attempting to invoke `POST /audit/events` receive HTTP 403 without `WWW-Authenticate` header.
- `AUDIT_WRITER` callers attempting to invoke `GET /audit/events` or `GET /audit/verify` receive HTTP 403 without `WWW-Authenticate` header.
- Valid `AUDIT_WRITER` credentials successfully append events (HTTP 201); valid `AUDITOR` credentials successfully query (HTTP 200) and verify (HTTP 200).
- Unmapped routes return HTTP 401 when unauthenticated and HTTP 403 when authenticated.
- Rejected (401/403) append requests never insert records or alter `audit_chain_head` sequence or hash.
- Production startup terminates with `IllegalStateException` when credentials are missing, shorter than 8 characters, or set to insecure defaults.

## Scenario B: Retention, Redaction, and Export

### Requirements

- Records older than a configurable retention window must be archivable or soft-deletable without false chain failures. *(Implemented and verified in Milestone 9)*
- Sensitive payload fields must be redactable without breaking tamper evidence. *(Implemented and verified in Milestone 10)*
- Export all records for an `actorId` or `resourceId` as a self-contained verifiable bundle.
- Document the redaction design, alternatives, limitations, and trade-offs.

### Assumptions

- The prototype retains immutable event evidence while presenting archived and redacted read projections.
- Archival status is managed via separate metadata (`audit_event_archive`) created in Flyway migration V3.
- Redaction metadata and state transitions are managed via separate metadata (`audit_event_redaction`) created in Flyway migration V4.

### Recommendations and implementation decisions

- **Retention via soft archival**: Implemented with separate `audit_event_archive` metadata keyed by `event_id` (PK FK to `audit_event.event_id`). Archiving an event never mutates or deletes rows in `audit_event`.
- **Configurable retention window**: Configured via `audit.retention.window-days`. Safe defaults are provided for `local` (90 days) and `test` (30 days); production environments strictly require an explicit positive value ($> 0$), validated at application startup.
- **Atomic, idempotent archival endpoints**: `POST /audit/archive/{eventId}` for targeted single-event archival and `POST /audit/archive/eligible` for batch archival of records older than the cutoff ($now - windowDays$). Both endpoints use `ON CONFLICT (event_id) DO NOTHING` for idempotent retry safety and are restricted to `AUDIT_WRITER`.
- **Preserved global verification**: `GET /audit/verify` streams directly from `audit_event` and validates 100% of events from genesis to chain head, guaranteeing zero false-positive chain failures for legitimately archived or redacted events.
- **Default query exclusion**: `GET /audit/events` omits archived records by default (`includeArchived=false`). Callers requesting `includeArchived=true` receive active and archived records with `archivedAt` populated.
- **Structured payload redaction (Option A Pluggable KeyManager)**:
  - Sensitive payload fields can be wrapped in an `EncryptedEnvelope` (AES-256-GCM) at ingestion.
  - Dedicated endpoint `POST /audit/events/{eventId}/redact`, restricted to `AUDIT_WRITER`.
  - For encrypted envelopes, invokes `KeyManager.destroyKey(keyId)` for true cryptographic erasure (crypto-shredding, `redaction_type = 'CRYPTO_SHREDDED'`).
  - For legacy plaintext events (Milestones 1–9), soft-masking is registered (`redaction_type = 'MASKED'`) without touching historical database records.
  - Appends an immutable `PAYLOAD_REDACTED` meta-audit event with coordinate metadata and **zero sensitive plaintext**.
  - Exactly-once logical meta-auditing is enforced via durable `operation_id = "redact:" + event_id + ":" + field_path` and pre-append reconciliation discovery against `audit_event ((payload->>'redactionOperationId'))`, ensuring network retries or crashes never duplicate meta-events.
  - Database enforcement (Flyway V4): column-level grants restrict `audit_app` to `UPDATE (status, redacted_at, meta_audit_sequence_no)` only; lifecycle triggers prevent metadata tampering and permanently seal records once `COMPLETED`; delete triggers prohibit `DELETE` and `TRUNCATE`.
  - Prototype key management: `InMemoryKeyManager` software implementation is provided strictly for test/prototype validation; its production limitations (in-memory volatility, JVM heap scraping, lack of HSM isolation) are explicitly documented.
  - Read projection masking: `GET /audit/events` masks completed redacted fields with `"[REDACTED]"` while preserving original `contentHash` and `recordHash`.
- **Verifiable export bundle (`GET /audit/exports`)**:
  - Implemented with mutual exclusivity between `actorId` and `resourceId` (exactly one required, blank rejected with HTTP 400).
  - Defaults `includeArchived` to `true` to ensure completeness of regulatory bundles; allows `includeArchived=false` to demote archived events to witness records.
  - Generates versioned, self-contained bundles (`bundleVersion: "1.0"`) under point-in-time snapshot-consistent read transactions (`@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)`).
  - Enforces configurable upper bounds (`AuditExportProperties` with `maxMatchedEvents = 1000` and `maxTotalRecords = 10000`), rejecting oversized export requests immediately with HTTP 413 `Payload Too Large` to safeguard against memory exhaustion.
  - Includes full canonical events for matched records and compact, privacy-preserving witness nodes $(\text{sequenceNo}, \text{previousHash}, \text{contentHash}, \text{recordHash})$ for non-matching records, establishing an unbroken genesis-to-head hash chain.
  - Cross-milestone synthesis: soft-archived records have `archivedAt` populated while physical rows remain immutable; crypto-shredded envelopes preserve ciphertext for exact hash recalculation (`INTACT`); legacy masked records mask projections with `"[REDACTED]"` and verify chain commitments as `PARTIALLY_VERIFIED_REDACTED` without falsely asserting payload content-hash matching.
  - Zero sensitive plaintext or destroyed keys are disclosed in witness records or projections.
  - Independent verification: verified via `StandaloneExportVerifier` (Java) and `scripts/verify_export.py` (Python 3 standard library).

### Acceptance criteria

- Archiving does not alter verification of the complete chain. *(Verified in `AuditVerificationIntegrationTests` and `AuditArchivalServiceIntegrationTests`)*
- Normal queries omit archived events by default, but expose them with `archivedAt` when explicitly requested. *(Verified in `AuditQueryIntegrationTests`)*
- A redacted response never exposes protected plaintext, while the original ciphertext envelope remains verifiable and `GET /audit/verify` returns `INTACT`. *(Verified in `AuditRedactionServiceIntegrationTests`)*
- Retrying redaction is idempotent and never creates duplicate meta-audit events. *(Verified in `AuditRedactionServiceIntegrationTests`)*
- An exported bundle verifies selected event content and chain continuity using only its contents, subject to the trusted-anchor limitation. Crypto-shredded events verify as `INTACT`, and legacy masked events verify chain linkage as `PARTIALLY_VERIFIED_REDACTED`. *(Verified in `AuditExportControllerWebMvcTest`, `StandaloneExportVerifierTest`, `AuditExportIntegrationTests`, and `AuditSecurityIntegrationTests`)*

## Scenario C: Compliance Reporting

### Requirements

- Clarify the intentionally ambiguous request that regulators need to audit access to client account data.
- Record ambiguities, questions or assumptions, the normalized requirement, resulting technical design, and implementation scope boundary.
- Implement the selected scope or provide a well-reasoned partial implementation.

### Unresolved product questions

- Which access actions count: read, search, export, administrative access, failed access, or all of them?
- Which actor types and client-account identifiers must be captured?
- Which regulators may query or receive exports, and what authorization and output format apply?
- What retention duration, legal hold behavior, and redaction rules apply?
- What reporting interval, completeness standard, and evidence of export authenticity are required?

### Provisional normalized requirement

For the prototype, record each successful or failed account-data access with actor, action, account resource identifier, server-recorded time, and structured access context. Auditors can query and export this data under the normal audit authorization model. Regulatory-specific identity, retention duration, legal hold, and format requirements remain documented scope boundaries until clarified.

## Cross-cutting delivery requirements

- Work in a private GitHub repository with an authentic development history.
- Include an `ATTESTATION.md` file with the candidate's supplied identity and required attestation text before submission.
- Provide runnable setup instructions, architecture, API/schema design, tests, limitations, trade-offs, final summary, and AI traceability.
- The candidate retains engineering ownership, reviews AI output, and can defend decisions and modify the solution live.

## Decisions requiring explicit human approval

- The final redaction and key-management policy, including whether cryptographic erasure is acceptable for the intended privacy obligation.
- Any production claim about protection from a database administrator.
- The Scenario C scope selected after product questions are answered.
- The candidate identity and dates inserted into `ATTESTATION.md`.
