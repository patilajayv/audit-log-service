# Testing Strategy and Implementation Backlog

## Test strategy

| Test level | Scope |
| --- | --- |
| Unit | Canonical JSON, timestamp handling, SHA-256 values, genesis behavior, violation classification, and request validation. |
| Repository and transaction integration | PostgreSQL constraints, head-row locking, atomic rollback, concurrent appends, filters, and pagination. |
| API integration | Write, query, and verify endpoints with realistic request and response contracts. |
| Security | `401` for unauthenticated calls, `403` for insufficient roles, and successful authorized writer/auditor flows. |
| Tamper demonstration | Append events, verify intact status, alter a row using an administrative connection, then assert the first reported violation. |
| Scenario B | Archived rows still verify, redacted projections hide plaintext, and exported bundles verify selected records and witnesses. |

Quality gates for each implementation milestone are relevant unit and integration tests, `git diff --check`, configuration validation, and documented manual verification where an automated test cannot demonstrate an operational control.

## Milestone 3 validation status

Milestone 3 completed the PostgreSQL runtime configuration, V1/V2 event and chain-head schema/linkage migrations, application-role grants, and append-only protections. The Scenario B archive-metadata migration remains deferred, along with the archival workflow.

Manual validation against an isolated disposable PostgreSQL database confirmed Flyway `V1` and `V2` application, role privileges, linked event/head advancement, rejected invalid transitions, and rollback without partial database state. The validation used synthetic repeated-character hashes and did not validate cryptographic correctness.

On 2026-10-15, Java 17.0.16 ran the five focused V2 migration tests successfully (0 failures, 0 errors, 0 skipped), then the full Maven suite successfully (16 tests: 1 application-context test and 15 PostgreSQL integration tests; 0 failures, 0 errors, 0 skipped). The V2 migration tests cover a valid genesis chain and four malformed V1 states; the failing migrations preserve the existing event/head data and do not leave V2-only triggers/functions or a successful V2 history entry. The integration tests use a Flyway-clean schema in a dedicated Testcontainers PostgreSQL instance rather than the separately used validation databases or containers. The suite includes direct database-level concurrent transaction contention coverage; application-level concurrent appends, the append API, and the full end-to-end audit workflow remain unverified. Synthetic repeated-character hashes do not establish cryptographic hash correctness.

## Milestone 4 validation status

Milestone 4 completed RFC 8785 (JCS) canonical hashing and the transactional `AuditAppendService` backed by PostgreSQL chain-head row locking.

The full Maven test suite passed under Java 17.0.16 with **63 tests run, 0 failures, 0 errors, and 0 skipped**:

- **`AuditHashServiceTest` (29 tests)**: Verified against independent hardcoded test vectors calculated with external oracles; tests cover negative zero normalization, integer-valued float normalization without decimals, scientific notation, subnormal IEEE-754 values, safe integer boundaries $[-(2^{53}-1), 2^{53}-1]$, rejection of unsafe integers (`Long.MAX_VALUE`, `Long.MIN_VALUE`, `BigInteger`), rejection of non-finite floats (`NaN`, `Infinity`), string encoding preservation for large numbers, decimal ECMAScript binary64 formatting, and duplicate property rejection.
- **`AuditAppendServiceIntegrationTests` (18 tests)**: Verified against dedicated, isolated Testcontainers PostgreSQL instances; tests cover appending the first event from genesis, chaining a second event to the first record hash, deterministic content and record hash matching, atomic rollback on head-advancement failure via deferred constraint triggers, invalid request validation (null/blank fields, non-object payload), and serialized concurrent appends producing distinct contiguous sequences without gaps or collisions.
- **`FlywayMigrationIntegrationTests` (15 tests)**: Confirms V1/V2 migration baseline, trigger protections, and rollback on malformed existing state.
- **`AuditLogServiceApplicationTests` (1 test)**: Confirms Spring Boot application context loads cleanly with configured mock dependencies.

## Milestone 5 validation status

Milestone 5 implemented and committed locally as `53d5bcb` (unpushed to `origin`) the event creation REST API (`POST /audit/events`), 1 MiB request body size enforcement via `RequestBodySizeLimitFilter`, strict duplicate-key rejection (root and nested), timestamp normalization, and sanitized error handling. Live smoke tests against an isolated local PostgreSQL 16 database on `127.0.0.1:5433` confirmed migration and runtime behavior.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **88 tests run, 0 failures, 0 errors, and 0 skipped**:

- **`AuditEventControllerWebMvcTest` (18 tests)**: MockMvc unit tests covering successful event creation (HTTP 201), omitted optional `sourceTimestamp`, offset-bearing timestamp normalization to UTC `Instant`, string preservation for large numbers, validation rejection for missing/blank fields (HTTP 400), rejection of null and non-object payloads (HTTP 400), malformed JSON syntax rejection (HTTP 400), invalid timestamp syntax rejection (HTTP 400), unsafe integer rejection (HTTP 400), strict duplicate JSON-key rejection at top level and nested payload (HTTP 400), declared oversized body rejection (HTTP 413), chunked oversized body rejection (HTTP 413), chain-head lock contention translation to HTTP 503 with `Retry-After: 1`, database error sanitization suppressing internal SQL/table/constraint details (HTTP 500), and unsupported media type rejection (HTTP 415).
- **`AuditEventControllerIntegrationTests` (7 tests)**: Full HTTP-to-database integration tests against isolated Testcontainers PostgreSQL with random port and `TestRestTemplate`; tests cover genesis append creating sequence 1, consecutive appends chaining sequence 1 and 2 with offset timestamps normalized to UTC in PostgreSQL, 8-thread concurrent HTTP appends committing contiguous sequences 1..8 with unbroken cryptographic previous-hash links, oversized requests (> 1 MiB) rejected with HTTP 413 without database insertion or head advancement, validation failure rejected with HTTP 400 without database insertion or head advancement, and duplicate keys at root and nested payload rejected with HTTP 400.
- **Previous baseline tests (63 tests)**: `AuditHashServiceTest` (29 tests), `AuditAppendServiceIntegrationTests` (18 tests), `FlywayMigrationIntegrationTests` (15 tests), and `AuditLogServiceApplicationTests` (1 test) continue to pass without regression.

### Live isolated database smoke-test results (2026-10-15)

The service was launched against an isolated PostgreSQL 16 container (`audit-log-service-postgres-1`) mapped to `127.0.0.1:5433` to coexist with host services on port 5432:

- **Flyway migrations**: Automatically applied `V1__create_audit_chain_schema.sql` and `V2__enforce_chain_head_event_linkage.sql` as `audit_migrator` during Spring Boot application context startup under profile `local`.
- **Live HTTP 201 append**: Submitted valid event via `curl`; received HTTP 201 with `sequenceNo: 1`, genesis `previousHash`, and valid SHA-256 hashes. Database verified: exactly 1 row in `audit_event` and `audit_chain_head.last_sequence_no = 1`.
- **Live HTTP 400 validation**: Submitted JSON with duplicate key (`"eventType"`); received HTTP 400 with sanitized message `"Duplicate JSON property: 'eventType'"`. Submitted malformed JSON; received HTTP 400 with `"Malformed JSON request body"`.
- **Live HTTP 413 payload limit**: Submitted a 1.1 MiB payload; received HTTP 413 with `"Request payload exceeds maximum allowed size of 1048576 bytes"`.
- **Database integrity check**: Verified `audit_event` count remained exactly 1 and `audit_chain_head.last_sequence_no` remained 1. Rejected requests did not insert records or advance the chain head.
- **Log privacy check**: Verified application logs contain only `eventId`, `sequenceNo`, and request `correlationId`; no `actorId`, `resourceId`, or `payload` data was logged.

## Milestone 6 validation status

Milestone 6 implemented the read-only audit event query REST API (`GET /audit/events`) backed by `AuditQueryService`, supporting multi-criteria filtering (`actorId`, `resourceType`, `resourceId`, `eventType`, and ISO-8601 UTC time range on `recorded_at`), validated pagination limits (`page >= 0`, `1 <= size <= 100`), deterministic ordering by `sequence_no ASC`, parameterized SQL queries, sanitized error responses, and operational log privacy. Milestone 6 changes are currently uncommitted locally pending review.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **107 tests run, 0 failures, 0 errors, and 0 skipped**:

- **`AuditEventQueryControllerWebMvcTest` (9 tests)**: MockMvc slice tests covering default pagination (`page=0, size=20`), complete filter binding, response DTO schema structure, HTTP 400 for negative page index, HTTP 400 for size < 1, HTTP 400 for size > 100, HTTP 400 for blank filter parameters, HTTP 400 for malformed ISO-8601 timestamps, HTTP 400 for `from > to` inverted time bounds, and HTTP 400 for non-integer query parameter type mismatches.
- **`AuditQueryIntegrationTests` (10 tests)**: End-to-end HTTP-to-database integration tests against isolated Testcontainers PostgreSQL 16; tests cover empty database queries, 15-event multi-page deterministic pagination strictly monotonic by `sequence_no ASC` without duplicate or skipped events, exact `actorId` filtering, `resourceType` and `resourceId` independent and combined filtering, `eventType` filtering, `recorded_at` timestamp range filtering with inclusive boundaries, multi-criteria filter intersection, no-match empty page responses, read-only database invariant assertion (verifying event counts, sequence counters, and `audit_chain_head.last_sequence_no` and `last_record_hash` are completely unchanged), and HTTP validation error sanitization.
- **Previous baseline tests (88 tests)**: `AuditEventControllerWebMvcTest` (18 tests), `AuditEventControllerIntegrationTests` (7 tests), `AuditHashServiceTest` (29 tests), `AuditAppendServiceIntegrationTests` (18 tests), `FlywayMigrationIntegrationTests` (15 tests), and `AuditLogServiceApplicationTests` (1 test) continue to pass without regression.

## Milestone 7 validation status

Milestone 7 implemented the complete-chain verification REST API (`GET /audit/verify`) backed by `AuditVerificationService`, performing cryptographic hash chain recomputation, sequence contiguity verification, genesis previous-hash check, RFC 8785 canonical content hash validation, record hash recomputation, and chain-head pointer validation using streaming cursors (`fetchSize = 500`) and immediate violation stoppage. Milestone 7 changes are currently uncommitted locally pending review.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **125 tests run, 0 failures, 0 errors, and 0 skipped**:

- **`AuditEventVerifyControllerWebMvcTest` (3 tests)**: MockMvc slice tests covering intact chain responses (`200 OK` with `status: INTACT`), corrupted chain responses with structured violation details (`200 OK` with `status: CORRUPTED`), and correlation ID propagation.
- **`AuditVerificationIntegrationTests` (15 tests)**: End-to-end HTTP-to-database integration tests against isolated Testcontainers PostgreSQL 16; tests cover:
  - Empty database verification (intact, genesis hash, 0 verified records).
  - Single-event chain verification (intact, sequence 1, matching head hash).
  - 10-event multi-event chain verification (intact, unbroken chain pointers, matching head hash).
  - Tamper test 1 (alter payload): detects `CONTENT_HASH_MISMATCH` at sequence 3.
  - Tamper test 2 (alter stored content hash): detects `CONTENT_HASH_MISMATCH` at sequence 2.
  - Tamper test 3 (alter genesis previous hash): detects `GENESIS_MISMATCH` at sequence 1.
  - Tamper test 4 (alter middle previous hash): detects `PREVIOUS_HASH_MISMATCH` at sequence 3.
  - Tamper test 5 (alter stored record hash): detects `RECORD_HASH_MISMATCH` at sequence 2.
  - Tamper test 6 (delete middle event): detects `SEQUENCE_GAP` at sequence 2 (expected 2, found 3).
  - Tamper test 7 (delete initial event): detects `SEQUENCE_GAP` at sequence 1 (expected 1, found 2).
  - Tamper test 8 (delete trailing event): detects `CHAIN_HEAD_MISMATCH` at sequence 3 (head expects 3, verified 2).
  - Tamper test 9 (alter chain head record hash): detects `CHAIN_HEAD_MISMATCH`.
  - Tamper test 10 (alter chain head sequence number): detects `CHAIN_HEAD_MISMATCH`.
  - Missing chain head row: detects `CHAIN_HEAD_MISMATCH` with missing head record diagnostic message.
  - Read-only invariant check: asserts row counts and chain-head values are 100% unaltered after multiple verification calls.
- **Previous baseline tests (107 tests)**: `AuditEventControllerWebMvcTest` (18 tests), `AuditEventControllerIntegrationTests` (7 tests), `AuditEventQueryControllerWebMvcTest` (9 tests), `AuditQueryIntegrationTests` (10 tests), `AuditHashServiceTest` (29 tests), `AuditAppendServiceIntegrationTests` (18 tests), `FlywayMigrationIntegrationTests` (15 tests), and `AuditLogServiceApplicationTests` (1 test) continue to pass without regression.

## Milestone 8 validation status

Milestone 8 implemented stateless HTTP Basic authentication, BCrypt password hashing, and role-based access control across all audit service endpoints, with sanitized 401/403 error responses, external credential sourcing, fail-fast production startup validation, and database immutability verification. Committed locally as `d69a172`.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **145 tests run, 0 failures, 0 errors, and 0 skipped**:

- **`AuditSecurityIntegrationTests` (13 tests)**: End-to-end HTTP-to-database security integration tests against isolated Testcontainers PostgreSQL 16:
  - `POST /audit/events`: unauthenticated request returns HTTP 401 with `WWW-Authenticate: Basic realm="AuditLogService"` and sanitized `ErrorResponse`.
  - `POST /audit/events`: invalid credentials return HTTP 401 with `WWW-Authenticate` header.
  - `POST /audit/events`: caller with `AUDITOR` role returns HTTP 403 Forbidden without `WWW-Authenticate` header.
  - `POST /audit/events`: caller with `AUDIT_WRITER` role succeeds with HTTP 201 Created and advances chain.
  - `GET /audit/events`: unauthenticated request returns HTTP 401 with `WWW-Authenticate` header.
  - `GET /audit/events`: caller with `AUDIT_WRITER` role returns HTTP 403 Forbidden.
  - `GET /audit/events`: caller with `AUDITOR` role succeeds with HTTP 200 OK.
  - `GET /audit/verify`: unauthenticated request returns HTTP 401 with `WWW-Authenticate` header.
  - `GET /audit/verify`: caller with `AUDIT_WRITER` role returns HTTP 403 Forbidden.
  - `GET /audit/verify`: caller with `AUDITOR` role succeeds with HTTP 200 OK.
  - Unmapped route: unauthenticated request returns HTTP 401 with `WWW-Authenticate` header.
  - Unmapped route: authenticated caller returns HTTP 403 Forbidden (default deny).
  - Database immutability verification: rejected (401/403) append attempts strictly leave row counts, sequences, and chain head untouched.
- **`SecurityCredentialValidationTests` (7 tests)**: Spring `ApplicationContextRunner` tests verifying production credential sourcing and fail-fast startup validation:
  - Rejection when writer username is missing in production mode (`IllegalStateException`).
  - Rejection when writer password is missing in production mode (`IllegalStateException`).
  - Rejection when password length is under 8 characters (`IllegalStateException`).
  - Rejection when password is an insecure placeholder (`writer-secret`, `password`, etc.) in production mode.
  - Successful startup with dedicated strong production credentials.
  - Successful startup in `test` profile with safe test defaults.
  - Successful startup in `local` profile with safe local defaults.
- **Previous baseline tests (125 tests)**: All 18 append WebMvc tests, 7 append integration tests, 9 query WebMvc tests, 10 query integration tests, 3 verify WebMvc tests, 15 verify integration tests, 29 hash unit tests, 18 append service tests, 15 Flyway migration tests, and 1 smoke test continue to pass with 0 regressions.

## Milestone 9 validation status

Milestone 9 implemented configurable retention and soft-archival metadata management (Scenario B), Flyway V3 schema migration, atomic and idempotent single-event and batch archival endpoints (`POST /audit/archive/{eventId}`, `POST /audit/archive/eligible`), fail-fast production startup validation, default query exclusion (`includeArchived=false`), and chain verification preservation. Milestone 9 changes are uncommitted locally pending review.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **177 tests run, 0 failures, 0 errors, and 0 skipped** (32 new tests added):

- **`AuditArchivalControllerWebMvcTest` (5 tests)**: MockMvc controller slice tests for archival endpoints:
  - Single event archive returns HTTP 200 with `ArchiveEventResult`.
  - Batch eligible archive returns HTTP 200 with count and cutoff timestamp.
  - Non-existent event returns HTTP 404 with sanitized `ErrorResponse`.
  - Invalid UUID format in route parameter returns HTTP 400 Bad Request.
  - Unsupported HTTP method (`DELETE /audit/archive/{eventId}`) returns HTTP 405 Method Not Allowed.
- **`AuditRetentionValidationTests` (6 tests)**: Spring `ApplicationContextRunner` tests verifying retention configuration and startup safety:
  - Production mode without configured window-days terminates startup (`IllegalStateException`).
  - Production mode with negative window-days terminates startup (`IllegalStateException`).
  - Production mode with zero window-days terminates startup (`IllegalStateException`).
  - Production mode with valid positive window-days boots successfully.
  - `test` profile defaults to 30 days and boots successfully.
  - `local` profile defaults to 90 days and boots successfully.
- **`AuditArchivalServiceIntegrationTests` (9 tests)**: End-to-end service and database integration tests against isolated Testcontainers PostgreSQL 16:
  - Single event archive creates metadata in `audit_event_archive` with matching `eventId`, UTC `archivedAt`, and policy ref.
  - Single event archive is strictly idempotent (subsequent call returns `archived: false` with original timestamp).
  - Archiving a non-existent UUID throws `AuditEventNotFoundException`.
  - Batch archive archives only events older than the UTC cutoff calculated once per batch.
  - Batch archive is strictly idempotent (subsequent batch run returns 0 newly archived records).
  - Hash immutability: `content_hash`, `record_hash`, and `previous_hash` on `audit_event` are verified identical before and after archival.
  - Trigger immutability: direct `UPDATE`, `DELETE`, and `TRUNCATE` against `audit_event` continue to be blocked by PostgreSQL triggers even when archive rows exist.
  - Full-chain verification intact: `AuditVerificationService.verifyChain()` confirms `INTACT` across all records before and after archival of intermediate and trailing events.
  - Retention window validation: batch archival rejects unconfigured, null, zero, or negative retention windows with `IllegalArgumentException`.
- **`AuditSecurityIntegrationTests` (18 tests, 5 new)**: Security role verification on archival routes:
  - `POST /audit/archive/{eventId}` unauthenticated returns HTTP 401 with `WWW-Authenticate` header.
  - `POST /audit/archive/{eventId}` with `AUDITOR` role returns HTTP 403 Forbidden.
  - `POST /audit/archive/{eventId}` with `AUDIT_WRITER` role succeeds (HTTP 200).
  - `POST /audit/archive/eligible` unauthenticated returns HTTP 401 with `WWW-Authenticate` header.
  - `POST /audit/archive/eligible` with `AUDITOR` role returns HTTP 403 Forbidden.
  - `POST /audit/archive/eligible` with `AUDIT_WRITER` role succeeds (HTTP 200).
- **`AuditQueryIntegrationTests` (13 tests, 3 new)**: Archival query behavior:
  - Query with default `includeArchived=false` omits archived records from page results and total count.
  - Query with `includeArchived=true` includes archived records and exposes populated `archivedAt` timestamps.
  - Database read-only invariant: querying with archival filters never mutates event or archive tables.
- **`FlywayMigrationIntegrationTests` (17 tests, 2 new)**: Flyway V3 migration structure and database grants:
  - Schema inspection confirms `audit_event_archive` foreign key constraint to `audit_event(event_id)`, non-null columns, and index on `archived_at`.
  - Application role `audit_app` privileges verified: `SELECT` and `INSERT` are permitted, while `UPDATE`, `DELETE`, and `TRUNCATE` are denied by PostgreSQL permission checks.
- **`AuditVerificationIntegrationTests` (16 tests, 1 new)**:
  - `testVerifyChainWithArchivedEvents`: Verifies complete-chain verification remains `INTACT` when arbitrary events across the chain are archived.
- **`AuditEventQueryControllerWebMvcTest` (10 tests, 1 new)**:
  - Validates `includeArchived` query parameter parsing and response DTO mapping.
- **Previous baseline tests (145 tests)**: All 18 append WebMvc tests, 7 append integration tests, 9 query WebMvc tests, 10 query integration tests, 3 verify WebMvc tests, 15 verify integration tests, 13 security integration tests, 7 credential validation tests, 29 hash unit tests, 18 append service tests, 15 Flyway migration tests, and 1 smoke test continue to pass with 0 regressions.

## Milestone 10 validation status

Milestone 10 implemented structured payload redaction (Scenario B), pluggable key management with AES-256-GCM envelope encryption, forward-only Flyway V4 migration (`audit_event_redaction`), redaction REST API (`POST /audit/events/{eventId}/redact`), exactly-once logical meta-auditing (`PAYLOAD_REDACTED`) with pre-append ledger reconciliation discovery, database-enforced immutability and lifecycle triggers, backward-compatible soft-masking for legacy plaintext events, and read-projection masking (`"[REDACTED]"`).

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **203 tests run, 0 failures, 0 errors, and 0 skipped** (26 new tests added):

- **`AuditCryptoServiceTest` (5 tests)**: Unit tests for cryptographic operations and key lifecycle:
  - AES-256-GCM encryption and decryption roundtrip with 12-byte IV and 128-bit authentication tag.
  - Decrypting an envelope after key destruction throws `KeyDestroyedException`.
  - Tampered ciphertext is rejected by GCM tag verification (`GeneralSecurityException`).
  - Tampered IV is rejected by GCM tag verification (`GeneralSecurityException`).
  - `KeyManager.destroyKey` is strictly idempotent (subsequent destruction returns false without error).
- **`AuditRedactionControllerWebMvcTest` (6 tests)**: MockMvc controller slice tests for `POST /audit/events/{eventId}/redact`:
  - Valid redaction request returns HTTP 200 with structured `RedactionResult`.
  - Non-existent event returns HTTP 404 with sanitized `ErrorResponse`.
  - Missing field path in payload returns HTTP 400 Bad Request.
  - Validation failure on empty field path, reason, or requestedBy returns HTTP 400 Bad Request.
  - Key destruction failure in KMS returns HTTP 502 Bad Gateway with sanitized error message.
  - Non-POST request (e.g. GET) is rejected with HTTP 403 Forbidden by default deny.
- **`AuditRedactionServiceIntegrationTests` (9 tests)**: End-to-end integration tests against isolated Testcontainers PostgreSQL 16:
  - Plaintext legacy event redaction masks read projection without mutating `audit_event` rows, sequence numbers, or cryptographic hashes (`content_hash`, `record_hash`).
  - Appended `PAYLOAD_REDACTED` meta-event contains zero sensitive plaintext disclosure.
  - Complete-chain verification (`GET /audit/verify`) confirms `status: "INTACT"` before and after redactions.
  - Query API returns `"[REDACTED]"` in projected payload with original hashes intact.
  - Encrypted envelope redaction destroys DEK in `KeyManager` and achieves true cryptographic erasure (`redaction_type = "CRYPTO_SHREDDED"`).
  - Attempted decryption of shredded envelope throws `KeyDestroyedException`.
  - Redaction is strictly idempotent: repeated requests return original result and do not append duplicate meta-events.
  - Reconciliation discovery: an interrupted run that already appended a meta-event discovers it on retry and links its sequence number without duplicate append.
  - Concurrency: concurrent threads serialize cleanly and produce exactly one meta-event and one key destruction.
  - Multi-transaction concurrency: independent concurrent transactions lock with `SELECT ... FOR UPDATE` via `AuditRedactionCoordinator`, serialize cleanly, append exactly one meta-event, and return identical results.
  - Non-existent event throws `AuditEventNotFoundException` (HTTP 404).
  - Non-existent field path throws `IllegalArgumentException` (HTTP 400).
  - KMS failure transitions row to `KEY_DESTRUCTION_FAILED`, throws `RedactionKeyDestructionException`, appends no meta-event, and preserves ledger integrity.
- **`FlywayMigrationIntegrationTests` (21 tests, 4 new)**: Flyway V4 migration structure, privileges, and triggers:
  - `v4CreatesAuditEventRedactionTable`: confirms columns, data types, nullability, primary key, unique constraints, foreign keys, and indexes.
  - `v4EnforcesAuditAppPrivilegesOnRedactionTable`: confirms `audit_app` role has `SELECT`, `INSERT`, and restricted `UPDATE (status, redacted_at, meta_audit_sequence_no)` only; attempts to update immutable metadata (`reason`, `field_path`, etc.) fail with `42501 permission denied`; `DELETE` and `TRUNCATE` fail with permission denied.
  - `v4EnforcesRedactionLifecycleTrigger`: trigger rejects invalid transition `PENDING -> COMPLETED` directly; rejects transition to `COMPLETED` without valid `meta_audit_sequence_no`; permanently seals completed records (`55000: record is sealed and immutable once COMPLETED`); delete trigger prohibits `DELETE` and `TRUNCATE` even for administrative roles (`55000`).
  - `v4RejectsDuplicateMetaAuditOperationIdOnAuditEvent`: confirms partial unique index `idx_audit_event_meta_redaction_op` enforces uniqueness on `audit_event` for `PAYLOAD_REDACTED` events and rejects duplicate operation IDs with SQLState `23505`.
- **`AuditExportControllerWebMvcTest` (7 tests, NEW in Milestone 11)**:
  - `exportWithValidActorIdReturns200`: confirms HTTP 200, JSON schema, and parameter mapping for `actorId`.
  - `exportWithValidResourceIdReturns200`: confirms HTTP 200, JSON schema, and parameter mapping for `resourceId`.
  - `exportWithBothFiltersReturns400`: confirms mutual exclusivity rejection with HTTP 400 Bad Request.
  - `exportWithNeitherFilterReturns400`: confirms missing filter rejection with HTTP 400 Bad Request.
  - `exportWithBlankActorIdReturns400`: confirms whitespace-only `actorId` rejection with HTTP 400.
  - `exportWithBlankResourceIdReturns400`: confirms whitespace-only `resourceId` rejection with HTTP 400.
  - `exportPayloadTooLargeReturns413`: confirms rejection with HTTP 413 Payload Too Large when export exceeds configured bounds.
- **`StandaloneExportVerifierTest` (18 tests, NEW in Milestone 11)**:
  - `emptyChainVerifiesIntact`: confirms empty bundle with head sequence 0 and genesis hash verifies as INTACT.
  - `validMixedBundleVerifiesIntact`: confirms mixed matched events and witness nodes verify as INTACT.
  - `tamperedPayloadFailsContentHash`: confirms payload modification triggers `CONTENT_HASH_MISMATCH`.
  - `missingSequenceFailsSequenceGap`: confirms omitted sequence number triggers `SEQUENCE_GAP`.
  - `tamperedWitnessHashFails`: confirms altered witness hash triggers `RECORD_HASH_MISMATCH`.
  - `tamperedChainHeadFails`: confirms altered chain head checkpoint triggers `CHAIN_HEAD_MISMATCH`.
  - `eventFilterMismatchFails`: confirms event actorId mismatch with filter triggers rejection.
  - `legacyMaskedEventReturnsPartiallyVerifiedRedacted`: confirms legacy masked events return `PARTIALLY_VERIFIED_REDACTED` with verified chain linkage and unverified masked payload.
  - `cryptoShreddedEventReturnsIntact`: confirms crypto-shredded records with `EncryptedEnvelope` return `INTACT` and 100% content verified.
  - `tamperedCryptoShreddedEnvelopeFailsContentHash`: confirms tampered ciphertext in encrypted envelope triggers content hash failure (`CORRUPTED`).
  - `tamperedLinkageInMaskedEventFails`: confirms tampered `previousHash` in legacy masked event triggers previous hash failure (`CORRUPTED`).
  - `eventSequenceGreaterThanHeadFails`: confirms event with sequence number > chainHead is rejected with `CORRUPTED`.
  - `eventSequenceZeroOrNegativeFails`: confirms event with sequence number <= 0 is rejected with `CORRUPTED`.
  - `witnessSequenceOutOfBoundsFails`: confirms witness with sequence number outside valid range is rejected with `CORRUPTED`.
  - `duplicateEventSequenceFails`: confirms duplicate sequence numbers within events are rejected with `CORRUPTED`.
  - `duplicateWitnessSequenceFails`: confirms duplicate sequence numbers within witnesses are rejected with `CORRUPTED`.
  - `duplicateSequenceAcrossEventsAndWitnessesFails`: confirms sequence collisions across events and witnesses are rejected with `CORRUPTED`.
  - `pythonVerifierRejectsOutOfRangeAndDuplicates`: confirms standalone Python script `scripts/verify_export.py` rejects out-of-range and duplicate sequences with exit code 1.
- **`AuditExportIntegrationTests` (10 tests, NEW in Milestone 11)**:
  - `testExportEmptyDatabase`: confirms empty database returns 200 OK with valid empty bundle.
  - `testExportByActorIdWithWitnesses`: confirms sparse export by `actorId`, verifies via `StandaloneExportVerifier` (Java), and executes standalone Python script `scripts/verify_export.py` to assert exit code 0.
  - `testExportByResourceId`: confirms sparse export by `resourceId` and verification.
  - `testExportSoftArchivedEvents`: confirms soft-archived events (Milestone 9) are included with `archivedAt` populated when `includeArchived=true`, and demoted to witness nodes when `includeArchived=false`.
  - `testExportWithCryptoShreddedEvent`: confirms crypto-shredded records (Milestone 10) retain ciphertext envelope, recompute content hash cleanly, include the accompanying `PAYLOAD_REDACTED` meta-event, and verify as INTACT.
  - `testExportWithLegacyMaskedRedactedEvent`: confirms legacy plaintext redacted fields are masked (`"[REDACTED]"`) in export projections without leaking sensitive plaintext, and verifies as `PARTIALLY_VERIFIED_REDACTED` in both Java and Python verifiers.
  - `testCompletenessBoundaryDemonstration`: empirically demonstrates the documented completeness boundary (sparse-chain exports prove inclusion/authenticity, but cannot prove non-omission of events without zero-knowledge proofs or witness payload disclosure).
  - `testExportExceedingMaxMatchedEventsReturns413`: confirms bounded export enforcement rejecting requests matching > `maxMatchedEvents` with HTTP 413 Payload Too Large.
  - `testExportExceedingMaxTotalRecordsReturns413`: confirms bounded export enforcement rejecting requests where total chain > `maxTotalRecords` with HTTP 413 Payload Too Large.
  - `testExportTransactionSnapshotConsistency`: confirms `@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)` snapshot consistency.
- **`AuditSecurityIntegrationTests` (38 tests, 14 new in Milestone 12)**:
  - `getExports_unauthenticated_returns401`: confirms HTTP 401 with `WWW-Authenticate` header.
  - `getExports_writerRole_returns403`: confirms `AUDIT_WRITER` role is rejected with HTTP 403 Forbidden.
  - `getExports_auditorRole_returns200`: confirms `AUDITOR` role is authorized (HTTP 200).
  - 8 compliance endpoint tests: `GET /audit/compliance/account-access` and `/export` return 401 unauthenticated, 403 `AUDIT_WRITER`, 200 `AUDITOR`, 200 `REGULATOR`.
  - 6 regulator least-privilege tests: `ROLE_REGULATOR` receives 403 Forbidden on `/audit/events` (GET), `/audit/exports`, `/audit/verify`, `/audit/events` (POST), `/audit/archive/eligible`, and `/audit/events/{id}/redact`.
- **Previous baseline tests (243 tests)**: All 243 previously existing tests continue to pass with 0 regressions. Total test suite now stands at **272 passing tests**.

## Milestone 12 validation status

Milestone 12 implemented Scenario C: Regulator Auditing of Client Account Data Access, introducing:
1. `GET /audit/compliance/account-access`: Dedicated compliance query endpoint with mandatory `accountId`, server-side `resourceType = 'ACCOUNT'` isolation, default `includeArchived = true`, stable pagination by `sequence_no ASC`, and sanitized error translation.
2. `GET /audit/compliance/account-access/export`: Dedicated server-side constrained export endpoint forcing `resourceType = 'ACCOUNT'` and `resourceId = accountId`, preventing non-account resource exposure.
3. Fail-closed supervisory meta-auditing: Durably appends `REGULATORY_AUDIT_ACCESSED` and `REGULATORY_EXPORT_ACCESSED` records to `audit_event` prior to data disclosure; if append fails, the request terminates immediately with zero account data read or returned.
4. Supervisory recursion & query isolation: Supervisory events use `resourceType = 'COMPLIANCE_AUDIT'`, isolating them completely from account queries and preventing feedback loops and pagination drift, while preserving full-chain verification (`GET /audit/verify`).
5. Least-privilege role authorization: `ROLE_REGULATOR` is provisioned and restricted to compliance endpoints; general queries, exports, verification, write, archive, and redact endpoints return HTTP 403 Forbidden.
6. Zero Flyway migrations: Preserved migrations V1–V4 untouched.

### Automated test coverage

The full Maven test suite passed under Java 17.0.16 with **272 tests run, 0 failures, 0 errors, and 0 skipped** across 23 test classes:

- **`AuditComplianceControllerWebMvcTest` (7 tests, NEW in Milestone 12)**: MockMvc unit slice tests covering:
  - `queryWithValidAccountIdReturns200`: Validates HTTP 200, parameter mapping, and response page structure.
  - `queryWithMissingAccountIdReturns400`: Asserts missing `accountId` returns sanitized HTTP 400 Bad Request.
  - `queryWithBlankAccountIdReturns400`: Asserts whitespace-only `accountId` returns HTTP 400.
  - `exportWithValidAccountIdReturns200`: Validates HTTP 200 and export bundle structure.
  - `exportWithMissingAccountIdReturns400`: Asserts missing `accountId` on export returns HTTP 400.
  - `queryFailClosedLockContentionReturns503`: Asserts chain-head lock contention translates to HTTP 503 with `Retry-After: 1`.
  - `queryFailClosedDatabaseErrorReturns500`: Asserts database error translates to sanitized generic HTTP 500 without leaking SQL.
- **`AuditComplianceIntegrationTests` (6 tests, NEW in Milestone 12)**: End-to-end HTTP-to-database integration tests against Testcontainers PostgreSQL 16:
  - `testQueryAccountAccessFiltersByAccountAndResourceType`: Confirms account filtering and `resourceType = 'ACCOUNT'` isolation, supervisory `REGULATORY_AUDIT_ACCESSED` append, and exclusion of supervisory events from subsequent query results (infinite loop prevention).
  - `testQueryIncludesSoftArchivedEventsByDefault`: Confirms soft-archived account events are returned by default with `archivedAt` populated and excluded when `includeArchived = false`.
  - `testQueryWithOptionalFilters`: Confirms `actorId` and `eventType` filtering.
  - `testComplianceExportAndVerifiers`: Confirms compliance export produces a self-contained bundle verifying via Java `StandaloneExportVerifier` (`Status: INTACT`) and Python `scripts/verify_export.py` (`Status: INTACT`), and confirms supervisory `REGULATORY_EXPORT_ACCESSED` append.
  - `testFullChainVerificationIntactAfterComplianceOperations`: Confirms full-chain verification (`GET /audit/verify`) remains `status: INTACT` across 100% of rows (business and supervisory events).
  - `testRedactedAccountEventDisplaysMaskedProjection`: Confirms structured redaction (Milestone 10) displays `"[REDACTED]"` in query projection while accompanying `PAYLOAD_REDACTED` meta-event is returned.
- **`AuditSecurityIntegrationTests` (38 tests, 14 new in Milestone 12)**:
  - Validates authentication and authorization across all 4 caller states (unauthenticated, writer, auditor, regulator).
  - Confirms `ROLE_REGULATOR` is granted access to `/audit/compliance/account-access` and `/export` (200 OK).
  - Confirms `ROLE_REGULATOR` is forbidden (403 Forbidden) from `/audit/events` (GET), `/audit/exports`, `/audit/verify`, `/audit/events` (POST), `/audit/archive/eligible`, and `/audit/events/{id}/redact`.
- **`SecurityCredentialValidationTests` (9 tests, 2 new in Milestone 12)**:
  - Confirms production startup validation rejects missing regulator username and missing regulator password.
- **Previous baseline tests (243 tests)**: All 243 previously existing tests continue to pass without regression.

## Prioritized backlog

1. [x] Add detailed requirements, architecture, threat model, and acceptance criteria documentation. (Milestone 2)
2. [x] Implement PostgreSQL schema and V1/V2 migration foundations. (Milestone 3)
3. [x] Implement canonicalization and hash components with fixed test vectors. (Milestone 4)
4. [x] Implement transactional append with chain-head locking and persistence tests. (Milestone 4)
5. [x] Implement the event creation REST API (`POST /audit/events`) and validation tests. (Milestone 5)
6. [x] Implement filtered query API (`GET /audit/events`) and stable pagination. (Milestone 6)
7. [x] Implement complete-chain verification API (`GET /audit/verify`) and direct-database tampering demonstration tests. (Milestone 7)
8. [x] Add Spring Security, role authorization (`AUDIT_WRITER`, `AUDITOR`), and security tests. (Milestone 8, `d69a172`)
9. [x] Implement Scenario B configurable retention, soft archival (`POST /audit/archive/**`), Flyway V3 archive schema, and query filtering. (Milestone 9)
10. [x] Implement Scenario B structured payload redaction (`POST /audit/events/{eventId}/redact`), pluggable `KeyManager`, AES-256-GCM envelopes, crypto-shredding, Flyway V4 redaction metadata/triggers, and query projection masking. (Milestone 10)
11. [x] Implement verifiable export bundle (`GET /audit/exports`) with witness continuity chains. (Milestone 11)
12. [x] Implement Scenario C regulator auditing of client account access, compliance query and constrained export endpoints, fail-closed supervisory auditing, and least-privilege authorization. (Milestone 12)
13. [x] Add final setup, test, limitation, AI-traceability, attestation, and live-defense documentation. (Milestone 13)

## Milestone discipline

Before each commit, inspect the exact diff, run the relevant checks, report actual results, propose a commit message, and wait for approval. Record accepted, modified, and rejected AI suggestions with the related validation and commit in `AI_USAGE_LOG.md`.
