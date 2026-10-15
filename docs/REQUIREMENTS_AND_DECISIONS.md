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

## Scenario C: Compliance Reporting (Milestone 12)

### Requirements

- Clarify the intentionally ambiguous request that regulators need to audit access to client account data.
- Record ambiguities, stakeholder questions, assumptions made, the normalized requirement statement, resulting technical design, and implementation scope boundaries.
- Implement the selected compliance scope with production-grade rigor and verified zero-regression against existing milestones.

### Ambiguity analysis and production questions

| Ambiguity | Production Discovery Questions |
|---|---|
| **Data Plane vs. Audit Plane** | Does the Audit Log Service store client banking balances/trades, or does it record *access events* generated when users/services inspect account data? |
| **Scope of Access Actions** | Does "access" encompass views, searches, downloads, automated batch jobs, administrative overrides, failed unauthorized attempts, or modification actions? |
| **Regulator Access Pattern** | Do external examiners query APIs directly with credentials, or do compliance officers run exports on their behalf? If direct, what authorization applies? |
| **Supervisory Audit Requirement** | Does inspecting client account audit trails constitute an auditable access event under FINRA/SEC supervisory rules ("auditing the auditors")? |
| **Evidence Format & Proof** | Do regulators require paginated JSON queries, offline cryptographically verifiable bundles, or certified reports? |

### Normalized requirement statement

For this prototype, the service operates as the immutable *Audit Plane*. Upstream banking systems log standardized client account access events (`resourceType = 'ACCOUNT'`, `resourceId = accountId`). The service provides authenticated regulatory examiners (`ROLE_REGULATOR`) with:
1. A dedicated, paginated query endpoint (`GET /audit/compliance/account-access`) to inspect historical access events for a specified client account (`resourceType = 'ACCOUNT'`, `resourceId = accountId`), defaulting to comprehensive discovery (`includeArchived = true`).
2. A dedicated, server-side constrained export endpoint (`GET /audit/compliance/account-access/export`) to generate an offline, self-contained, cryptographically verifiable hash-chain bundle strictly scoped to the specified account.
3. Mandatory, fail-closed supervisory meta-auditing: each regulatory query and export appends an immutable `REGULATORY_AUDIT_ACCESSED` or `REGULATORY_EXPORT_ACCESSED` event to the ledger; if this append fails, the request aborts with zero account data disclosed.
4. Strict recursion prevention: supervisory audit records use `resourceType = 'COMPLIANCE_AUDIT'` and are isolated from account access results, guaranteeing stable pagination and zero query feedback loops while preserving full-chain verification.
5. Strict least-privilege enforcement: regulators are denied access to general audit queries (`/audit/events`), unrestricted exports (`/audit/exports`), full-chain verification (`/audit/verify`), and all write, archival, and redaction APIs.

### Implementation decisions

- **Server-side constrained export isolation**: `ROLE_REGULATOR` is denied access to general `GET /audit/exports` (HTTP 403 Forbidden). Regulatory exports use `GET /audit/compliance/account-access/export?accountId={accountId}` which forces `resourceType = 'ACCOUNT'` server-side. Intermediate events are demoted to hash witnesses, preventing unauthorized exposure of non-account resources. The bundle verifies 100% via `StandaloneExportVerifier` (Java) and `scripts/verify_export.py` (Python).
- **Fail-closed supervisory audit reliability**: Supervisory records are committed in dedicated write transactions prior to data retrieval. If the append fails (e.g. lock contention, database error), execution terminates immediately and returns sanitized HTTP 503/500 responses without disclosing client account data.
- **Query and pagination stability**: Paginated queries execute under single-request `READ COMMITTED` transactions ordered monotonically by `sequence_no ASC`. Newly appended records appear at the tail and never shift previously viewed page offsets. Point-in-time snapshot freezes are provided by the export endpoint under `@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)`.
- **Supervisory recursion prevention**: Supervisory events use `resourceType = 'COMPLIANCE_AUDIT'`. Account queries filter by `resourceType = 'ACCOUNT'`, preventing supervisory events from polluting the account's business audit trail or altering pagination offsets. Complete ledger verification (`GET /audit/verify`) validates 100% of rows from genesis to head without filtering.
- **Zero Flyway migrations**: Preserved Flyway migrations V1–V4 untouched. The existing composite index `(resource_type, resource_id)` from Flyway V1 fully accelerates compliance queries.
- **Least-privilege role separation**: `ROLE_REGULATOR` is authorized strictly for `/audit/compliance/account-access` and `/audit/compliance/account-access/export`. Internal operational endpoints (`/audit/events`, `/audit/exports`, `/audit/verify`, `/audit/archive/**`, `/audit/events/*/redact`) return HTTP 403 Forbidden.

### Documented production boundaries

1. **Subpoena and examination matter tracking**: In production, regulatory queries mandate an external subpoena or examination reference (e.g. `matterId = "SEC-EXAM-2026-04"`) in request headers to satisfy legal holds.
2. **Upstream banking data plane integration**: Business access events are emitted by upstream gateways (CRM, branch teller UI, advisor portal) via messaging queues (Kafka/Pulsar) with dead-letter replay.
3. **mTLS and federated PKI authentication**: External examiners authenticate via client certificate mTLS with hardware security tokens rather than HTTP Basic credentials.

### Acceptance criteria

- `GET /audit/compliance/account-access?accountId={id}` returns `200 OK` with matching account events ordered by `sequence_no ASC`. *(Verified in `AuditComplianceControllerWebMvcTest` and `AuditComplianceIntegrationTests`)*
- Missing or blank `accountId` returns sanitized `400 Bad Request`. *(Verified in `AuditComplianceControllerWebMvcTest`)*
- Soft-archived account events are included by default (`includeArchived = true`) and excluded when `includeArchived = false`. *(Verified in `AuditComplianceIntegrationTests`)*
- Structured redaction displays `"[REDACTED]"` for sensitive fields without mutating ledger rows. *(Verified in `AuditComplianceIntegrationTests`)*
- Each successful query and export appends an immutable `REGULATORY_AUDIT_ACCESSED` or `REGULATORY_EXPORT_ACCESSED` event to `audit_event`. *(Verified in `AuditComplianceIntegrationTests`)*
- Fail-closed behavior: supervisory append failure aborts the request with zero data disclosed. *(Verified in `AuditComplianceControllerWebMvcTest`)*
- Subsequent queries for the account exclude supervisory events from results and do not experience pagination drift. *(Verified in `AuditComplianceIntegrationTests`)*
- Full-chain verification (`GET /audit/verify`) passes with `status: "INTACT"` across both business and supervisory events. *(Verified in `AuditComplianceIntegrationTests`)*
- `GET /audit/compliance/account-access/export?accountId={id}` produces a self-contained bundle verifying as `INTACT` via `StandaloneExportVerifier` and `scripts/verify_export.py`. *(Verified in `AuditComplianceIntegrationTests`)*
- `ROLE_REGULATOR` is authorized for compliance endpoints (200 OK) and strictly forbidden (403 Forbidden) from `/audit/events`, `/audit/exports`, `/audit/verify`, and write/archive/redact endpoints. *(Verified in `AuditSecurityIntegrationTests`)*
- `ROLE_AUDITOR` is authorized for compliance endpoints; `ROLE_AUDIT_WRITER` is forbidden (403); unauthenticated callers receive 401. *(Verified in `AuditSecurityIntegrationTests`)*
- All 304 automated tests pass without regression. *(Verified in Maven test run)*

## Engineering Hardening & Production Operationalization (Milestone 14)

### Requirements

- Protect the ingestion endpoint against replay attacks, duplicate submissions, and network retries via client-scoped idempotency.
- Protect the service against unauthenticated Denial of Service (DoS) and authenticated credential exhaustion attacks via multi-tier rate limiting.
- Establish an automated CI/CD pipeline with continuous integration and JaCoCo code coverage quality gates.

### Implementation Decisions

1. **Two-Tier Rate Limiting Architecture**:
   - **Pre-Authentication IP Limiting (`PreAuthIpRateLimitingFilter`)**: Intercepts unauthenticated connection requests by IP address (default: 100 req/min, burst 20). Protects against unauthenticated brute-force credential stuffing and DoS attacks.
   - **Post-Authentication Principal Limiting (`PostAuthPrincipalRateLimitingFilter`)**: Enforces rate limits per authenticated principal (default: 60 req/min, burst 10). Protects against compromised API keys or runaway upstream scripts.
   - **Bounded `TokenBucketRateLimiter`**: Uses fine-grained per-key locks, nanosecond monotonic clock accounting (`System.nanoTime()`), and periodic background eviction of idle buckets to prevent heap memory exhaustion.
   - **Sanitized Throttling Response**: Emits HTTP 429 `Too Many Requests` with a standard `Retry-After: 1` header and sanitized JSON `ErrorResponse`.
2. **Client-Scoped Idempotency Protection**:
   - Supported via `Idempotency-Key` or `X-Idempotency-Key` header on `POST /audit/events`.
   - Flyway migration `V5__add_audit_idempotency.sql` creates `audit_idempotency_key` table keyed by `(client_id, idempotency_key)` with `SELECT, INSERT` privileges granted to `audit_app`.
   - Request payloads are canonically fingerprinted using RFC 8785 JSON Canonicalization Scheme (JCS) and hashed with SHA-256 over `{actorId, eventType, payload, resourceId, resourceType, sourceTimestamp}`.
   - Transactional head-locking protocol: In `AuditAppendService.appendWithIdempotency()`, under database transaction with chain-head row locking (`SELECT FOR UPDATE FROM audit_chain_head WHERE chain_id = 1`), checks existing key:
     - Exact match: returns original `AuditEventResponse` with HTTP 200 OK.
     - Payload mismatch: aborts with sanitized HTTP 409 Conflict.
     - New key: executes atomic event insert, chain-head advancement, and idempotency key recording, satisfying trigger `trg_audit_chain_head_advance` and returning HTTP 201 Created.
3. **CI/CD Pipeline & Code Coverage Enforcement**:
   - Official Apache Maven 3.9.9 wrapper (`mvnw`, `mvnw.cmd`).
   - GitHub Actions automated CI pipeline (`.github/workflows/ci.yml`) executing on every push and pull request against isolated Testcontainers PostgreSQL.
   - Automated Dependabot configuration (`.github/dependabot.yml`) for weekly Maven and Actions dependency updates.
   - JaCoCo coverage quality gate configured in `pom.xml` (`jacoco:check`) enforcing:
     - Line coverage: $\ge 85\%$ (actual: $89.78\%$)
     - Instruction coverage: $\ge 85\%$ (actual: $89.91\%$)
     - Branch coverage: $\ge 70\%$ (actual: $72.27\%$)
4. **Production Architecture Boundaries**:
   - **Distributed Rate Limiting**: In a multi-node Kubernetes cluster, rate limiting is terminated at the ingress/API gateway tier (e.g. Envoy, Kong) or backed by a distributed cache (e.g. Redis token bucket). `RemoteIpFilter` trusted proxy CIDRs must be configured to prevent header spoofing via untrusted `X-Forwarded-For`.
   - **Network & TLS Boundary**: Service container runs HTTP internally within a private VPC / service mesh (pod-to-pod mTLS); external TLS 1.3 is terminated at the ingress controller.
   - **External Trust Anchors**: Mathematical proof of immutability against a database superuser who could alter tables and recompute all hashes requires external trust anchors, such as RFC 6962 Certificate Transparency style signed tree heads (STHs), RFC 3161 cryptographic timestamping, or periodic publishing of signed checkpoints to WORM storage (AWS S3 Object Lock) or a public ledger.

### Acceptance Criteria

- Initial append with idempotency key returns HTTP 201 Created. *(Verified in `AuditSecurityIntegrationTests`)*
- Replay append with identical key and payload returns HTTP 200 OK with original event details. *(Verified in `AuditSecurityIntegrationTests`)*
- Replay append with identical key but mismatched payload returns HTTP 409 Conflict. *(Verified in `AuditSecurityIntegrationTests`)*
- Exceeding burst token allowance returns HTTP 429 Too Many Requests with `Retry-After: 1`. *(Verified in `RateLimitingFilterTest` and `RateLimitingSecurityIntegrationTests`)*
- All 304 automated tests pass and JaCoCo coverage metrics satisfy quality gate thresholds in automated CI. *(Verified in local test run and GitHub Actions CI)*

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
