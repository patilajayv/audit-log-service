# AI Usage Log

This log records AI-assisted work honestly. Each future entry will identify the task, prompt or context summary, AI output used, human decisions, modifications or rejections, validation performed, and related commit.

## 2026-10-14 - Milestone 1 foundation

- **Task:** Create the initial Maven, Spring Boot, Docker Compose, test, and setup-documentation foundation.
- **AI contribution:** Drafted the proposed file structure and starter configuration from the approved technology stack and milestone scope.
- **Engineer oversight:** The user constrained the repository location, prohibited including the assignment PDF, and required review before committing.
- **Decision:** Reviewed and approved by the engineer. Committed as `a5c384b` with message `chore: initialize audit log service foundation`.
- **Validation:** `mvn -Dmaven.repo.local=/private/tmp/audit-log-service-m2 test` passed: 1 test run, 0 failures, 0 errors, 0 skipped. `docker compose config` passed. `git diff --check` passed.

## 2026-10-14 - Milestone 2 requirements and architecture

- **Task:** Document requirements, architecture, acceptance criteria, threat model, API/schema contracts, and implementation sequencing before functionality is implemented.
- **AI contribution:** Drafted concise engineering documentation from the assignment requirements and the engineer-approved design decisions.
- **Engineer oversight:** The engineer approved server-assigned `recorded_at`, optional `source_timestamp`, SHA-256, deterministic versioned serialization, chain-head locking, stateless HTTP Basic roles, and Scenario A-first delivery scope.
- **Decision:** Pending engineer review. No application functionality was generated or changed.
- **Final review:** Added the required root `ATTESTATION.md` draft with the PDF-required attestation statement and placeholders for personal details and dates not supplied by the engineer.
- **Validation:** `git diff --check` passed. `docker compose config` passed. A sandboxed Maven test run failed because JDK 24 could not self-attach Mockito's agent; the same command with host JVM permissions passed: 1 test run, 0 failures, 0 errors, 0 skipped.

## 2026-10-14 - Milestone 3 PostgreSQL schema and migrations

- **Task:** Add Flyway-backed PostgreSQL schema foundations for immutable audit events and global chain-head metadata.
- **AI contribution:** Drafted the schema, role separation, append-only triggers, migration test plan, and local-profile configuration from the approved architecture.
- **Engineer oversight:** Preserved the approved single global chain, service-assigned sequence design, genesis hash, and separate migrator/application database roles. Deferred Scenario B archive metadata until its implementation milestone.
- **Decision:** Pending engineer review. No application API, hash implementation, controller, or authentication behavior was added.
- **Initial automated validation:** `docker compose config` passed. The initial Maven run completed with 10 tests run, 0 failures, 0 errors, and 9 skipped. The application-context test passed; the nine PostgreSQL migration integration tests were skipped because Testcontainers could not establish a usable connection to the Docker API during that run.
- **Follow-up automated validation (2026-10-15):** With Java 17.0.16, the five focused V2 migration tests passed (0 failures, 0 errors, 0 skipped), followed by the full Maven suite: 16 tests run, 0 failures, 0 errors, 0 skipped. The 15-test PostgreSQL integration class includes direct database-level concurrent append contention coverage. Test setup uses a Flyway-clean V1 schema in its dedicated Testcontainers PostgreSQL instance; it does not connect to the separately used validation databases or containers. The V2 rejection cases confirm the seeded event/head rows remain unchanged and that failed migration leaves no V2-only triggers/functions or successful V2 history entry.
- **Manual PostgreSQL validation reported by the engineer:** Flyway migration `V1` applied successfully to the disposable validation database. The initial `audit_chain_head` row had `chain_id = 1`, `last_sequence_no = 0`, and a 64-character all-zero genesis hash. `UPDATE`, `DELETE`, and `TRUNCATE` attempts against `audit_event` were rejected by the append-only trigger. The `audit_app` role had `SELECT` and `INSERT` privileges on `audit_event`, while `UPDATE`, `DELETE`, and `TRUNCATE` were denied. A direct attempt to advance `audit_chain_head.last_sequence_no` from 0 to 2 was rejected with `audit_chain_head sequence must advance by one`; a subsequent query confirmed the chain head remained at sequence 0 with the genesis hash.
- **Earlier manual validation limitations:** The trigger-validation row used placeholder hashes and was not a cryptographically valid audit-chain event. These checks validate migration, permissions, and trigger behavior only; they do not validate application hash computation or the future append workflow.
- **Manual isolated database validation:** Flyway validated and applied `V1` and `V2` to a separate disposable database isolated from the normal Compose database. The `audit_app` role had `INSERT` on `audit_event`, no `UPDATE` on `audit_event`, and `UPDATE` on `audit_chain_head`. One clearly synthetic event was committed at sequence 1 and the chain head advanced to its synthetic record hash. The database rejected an incorrect event previous hash, head advancement without a corresponding event, head advancement with a mismatched record hash, a commit that omitted the required head advancement, and a jump from sequence 1 to 3. After every rejected operation, the database retained exactly that one event and its original sequence-1 chain head; no partial changes persisted.
- **Manual validation limitations:** The isolated checks used repeated-character synthetic hashes. They validate database constraints and transaction behavior, not cryptographic hash correctness or tamper-proofness. The automated concurrency test covers competing direct database transactions, not the application-level append API or the full end-to-end audit workflow. The older disposable validation database may retain a synthetic orphan row from prior trigger testing and was not modified during this validation.

## 2026-10-15 - Milestone 4 canonical hashing and transactional append

- **Task:** Implement canonical audit event hashing and application-level transactional event append service.
- **AI contribution:**
  - Implemented `AuditHashService` and `AuditAppendService` based on Spring Boot, JDBC, and `io.github.erdtman:java-json-canonicalization:1.1`.
  - Replaced initial custom Jackson serializer with `java-json-canonicalization:1.1` following review of RFC 8785 (JCS) compliance (negative zero normalization, IEEE-754 exponent formatting, subnormal handling).
  - Implemented strict numeric validation in `validatePayload()` rejecting integers outside the safe IEEE-754 range [-(2^53 - 1), 2^53 - 1], non-finite numbers (NaN, Infinity), and overflowing decimals.
  - Enforced millisecond UTC truncation (`ChronoUnit.MILLIS`) for `recordedAt` and `sourceTimestamp` at ingestion.
  - Added independent hardcoded SHA-256 test vectors in `AuditHashServiceTest` using external oracles.
  - Implemented integration tests in `AuditAppendServiceIntegrationTests` covering genesis append, linked second event, rollback on deferred constraint trigger, request validation, and concurrent append serialization against isolated Testcontainers PostgreSQL.
- **Engineer oversight:**
  - Audited canonical JSON implementation against RFC 8785 and RFC 7493 requirements; rejected custom Jackson serializer in favor of a verified RFC 8785 library.
  - Mandated explicit numeric policy rejecting unsafe integers instead of silently losing precision.
  - Directed timestamp millisecond truncation at creation and ingestion.
  - Reviewed working tree diffs, test counts, and pre-commit status before approving local commit and push.
- **Decision:** Approved by the engineer. Committed as `2597c7f` with message `feat: implement canonical audit event hashing and append service` and pushed to `origin/main`.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditHashServiceTest`: 29 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditAppendServiceIntegrationTests`: 18 tests run, 0 failures, 0 errors, 0 skipped.
    - `FlywayMigrationIntegrationTests`: 15 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditLogServiceApplicationTests`: 1 test run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 63 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.
  - Independent verification: Expected hash constants in tests were independently verified using RFC 8785 reference values and external SHA-256 tools, avoiding self-referential oracles.

## 2026-10-15 - Milestone 5 REST API for audit event append

- **Task:** Expose audit event append functionality through `POST /audit/events`, enforce 1 MiB body size limit, duplicate JSON-key detection, error sanitization, timestamp normalization, and local isolated PostgreSQL 16 verification.
- **AI contribution:**
  - Implemented `AuditEventController`, mapping incoming `AppendEventRequest` to `AuditAppendService.append(request)` and returning `201 Created` with `AuditEventResponse`.
  - Implemented `RequestBodySizeLimitFilter` enforcing a 1 MiB threshold for declared `Content-Length` and chunked/streaming requests before deserialization, returning sanitized HTTP 413.
  - Configured Jackson `JsonParser.Feature.STRICT_DUPLICATE_DETECTION` to reject duplicate keys at both root request and nested payload levels per RFC 8785 §3.2.3.
  - Implemented `AuditControllerAdvice` providing sanitized error responses (`ErrorResponse`) for client errors (400), payload size (413), unsupported media types (415), chain-head lock contention (503 with `Retry-After: 1`), and database errors (500), suppressing internal SQL, constraint names, and stack traces.
  - Added operational logging privacy omitting `actorId`, `resourceId`, and event payloads, tracing via correlation IDs.
  - Created 18 MockMvc unit tests in `AuditEventControllerWebMvcTest` and 7 Testcontainers integration tests in `AuditEventControllerIntegrationTests`.
  - Configured local-only Compose port override (`127.0.0.1:5433:5432`) to isolate development container from native host PostgreSQL 14 on port 5432.
- **Engineer oversight:**
  - Rejected Tomcat multipart/servlet configuration in favor of servlet filter with stream-counting logic for pure JSON bodies.
  - Mandated strict duplicate-key detection at both root and nested payload levels.
  - Required error response sanitization without SQL or stack trace disclosure.
  - Mandated operational logging privacy (no actor IDs, resource IDs, or payloads logged).
  - Enforced isolation from native PostgreSQL 14 without stopping host services.
  - Reviewed pre-commit audit and approved local commit `53d5bcb`.
- **Decision:** Approved by the engineer. Committed locally as `53d5bcb` with message `feat: implement audit event append REST endpoint` (local commit; unpushed to `origin`).
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditEventControllerWebMvcTest`: 18 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventControllerIntegrationTests`: 7 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 88 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.
  - Live isolated database smoke testing against PostgreSQL 16 on `127.0.0.1:5433`:
    - Successful startup and Flyway `V1` and `V2` migration application under profile `local`.
    - Live `POST /audit/events` append returned HTTP 201 with `sequenceNo: 1` and genesis `previousHash`; verified 1 row in `audit_event` and `audit_chain_head.last_sequence_no = 1`.
    - Duplicate JSON key and malformed syntax returned HTTP 400.
    - 1.1 MiB payload returned HTTP 413.
    - Database verification confirmed rejected requests did not insert events or advance the chain head.
    - Log verification confirmed absence of sensitive data leakage or unexpected exceptions.

## 2026-10-15 - Milestone 6 query API and pagination

- **Task:** Implement read-only `GET /audit/events` query REST API with multi-criteria filtering, stable pagination, input validation, and read-only verification.
- **AI contribution:**
  - Implemented `AuditEventDto` representing all 13 stored database columns with immutable types and formatted ISO-8601 UTC timestamps.
  - Implemented `AuditPageResponse<T>` containing events list and pagination metadata (`page`, `size`, `totalElements`, `totalPages`, `first`, `last`).
  - Implemented `AuditQueryCriteria` with strict validation: `page >= 0`, `1 <= size <= 100`, non-blank filter strings, ISO-8601 UTC parsing on `from` and `to`, and `from <= to` check.
  - Implemented `AuditQueryService` using Spring `JdbcTemplate` with `@Transactional(readOnly = true)`. Used 100% parameterized SQL for count and select queries with `ORDER BY sequence_no ASC LIMIT ? OFFSET ?`.
  - Updated `AuditEventController` to expose `GET /audit/events`, delegating to `AuditQueryService`.
  - Updated `AuditControllerAdvice` with `MethodArgumentTypeMismatchException` handler returning sanitized HTTP 400 for query parameter conversion errors.
  - Created 9 MockMvc slice tests in `AuditEventQueryControllerWebMvcTest` and 10 end-to-end integration tests against Testcontainers PostgreSQL 16 in `AuditQueryIntegrationTests`.
- **Engineer oversight:**
  - Clarified consistency model: corrected documentation to state that separate requests under PostgreSQL `READ COMMITTED` isolation do not share a transaction snapshot across pages, while `sequence_no ASC` provides deterministic ordering for already-committed rows.
  - Mandated 100% parameterized SQL for all filter criteria; required count and select queries to apply identical filter predicates.
  - Mandated operational logging privacy (no actor IDs, resource IDs, or payloads logged).
  - Enforced verification that query execution never mutates database rows, sequences, or `audit_chain_head`.
  - Required tests covering filter combinations, timestamp boundaries, invalid parameters, page boundaries, stable ordering, and read-only behavior.
- **Decision:** Pending engineer review. Milestone 6 changes uncommitted locally.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditEventQueryControllerWebMvcTest`: 9 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditQueryIntegrationTests`: 10 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 107 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.

## 2026-10-15 - Milestone 7 audit chain verification and tamper detection

- **Task:** Implement complete-chain verification REST API (`GET /audit/verify`), cryptographic hash chain recomputation, sequence contiguity verification, genesis previous-hash check, RFC 8785 canonical content hash validation, record hash recomputation, and chain-head pointer validation with safe Testcontainers tampering tests.
- **AI contribution:**
  - Implemented `ChainViolationType` enum with 6 distinct violation categories (`GENESIS_MISMATCH`, `SEQUENCE_GAP`, `CONTENT_HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `RECORD_HASH_MISMATCH`, `CHAIN_HEAD_MISMATCH`).
  - Implemented `ChainViolation` record with structured diagnostic details (`type`, `sequenceNo`, `eventId`, `expected`, `actual`, `message`).
  - Implemented `AuditVerificationResponse` record cleanly separating declared chain-head metadata from verified values (`status`, `recordsVerified`, `headSequenceNo`, `headRecordHash`, `lastVerifiedSequenceNo`, `lastVerifiedRecordHash`, `violation`).
  - Implemented `AuditVerificationService` executing in `@Transactional(readOnly = true)` with cursor-based streaming (`fetchSize = 500`) via `PreparedStatement` and `ResultSetExtractor` that halts processing immediately at the first violation.
  - Implemented `AuditVerificationController` exposing `GET /audit/verify` with request correlation tracing and log privacy.
  - Implemented 3 MockMvc slice tests in `AuditEventVerifyControllerWebMvcTest`.
  - Implemented 15 end-to-end integration tests in `AuditVerificationIntegrationTests` against Testcontainers PostgreSQL 16 covering empty chain, single event, multi-event, 10 specific administrative tampering scenarios (payload alteration, stored content hash alteration, genesis hash alteration, middle previous hash alteration, record hash alteration, middle record deletion, first record deletion, trailing record deletion, chain head record hash alteration, chain head sequence number alteration), missing chain head row, and read-only database invariant assertions.
- **Engineer oversight:**
  - Mandated precise response semantics distinguishing declared head metadata from verified records.
  - Directed structured handling of a missing singleton `audit_chain_head` row as `CHAIN_HEAD_MISMATCH` instead of a generic database failure.
  - Required cursor-based streaming (`fetchSize = 500`) to avoid memory saturation and confirmed immediate violation stoppage.
  - Clarified the precise security boundary: internal verification detects corruption and tampering relative to the stored chain and head, but cannot detect full-chain rewriting by a superuser without an external trusted anchor.
  - Directed administrative tampering to be performed strictly within isolated Testcontainers databases using temporary trigger toggling, leaving production and local databases untouched.
- **Decision:** Approved by the engineer. Committed locally as `01d5460` with message `feat: implement audit chain verification and tamper detection` (local commit; unpushed to `origin`).
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditEventVerifyControllerWebMvcTest`: 3 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditVerificationIntegrationTests`: 15 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 125 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.

## 2026-10-15 - Milestone 8 authentication, authorization, and least-privilege access

- **Task:** Implement stateless HTTP Basic authentication, BCrypt password hashing, role-based authorization (`AUDIT_WRITER`, `AUDITOR`), sanitized 401/403 error handling, external credential sourcing with fail-fast production validation, and database immutability verification.
- **AI contribution:**
  - Added `spring-boot-starter-security` and `spring-security-test` to `pom.xml` compatible with Spring Boot 3.4.5 without upgrading Spring Boot.
  - Implemented `SecurityUserProperties` mapping external credentials for writer and auditor accounts.
  - Implemented `RestAuthenticationEntryPoint` emitting sanitized JSON `ErrorResponse` (401 Unauthorized) while preserving the `WWW-Authenticate: Basic realm="AuditLogService"` header.
  - Implemented `RestAccessDeniedHandler` emitting sanitized JSON `ErrorResponse` (403 Forbidden) without leaking internal security details.
  - Implemented `SecurityConfiguration` enforcing stateless session creation (`STATELESS`), disabling CSRF for stateless REST operations, encoding passwords with `BCryptPasswordEncoder`, registering in-memory user details, configuring role authorization (`POST /audit/events` -> `AUDIT_WRITER`, `GET /audit/events` -> `AUDITOR`, `GET /audit/verify` -> `AUDITOR`, and default deny `.anyRequest().denyAll()`), and validating production credentials at startup to reject empty or insecure placeholder defaults (`IllegalStateException`).
  - Isolated default development credentials to `local` profile in `application-local.yaml` and dedicated test credentials in `src/test/resources/application.yaml`.
  - Updated existing WebMvc slice tests (`AuditEventControllerWebMvcTest`, `AuditEventQueryControllerWebMvcTest`, `AuditEventVerifyControllerWebMvcTest`) with `@WithMockUser` and imported `SecurityConfiguration`.
  - Updated existing integration tests (`AuditEventControllerIntegrationTests`, `AuditQueryIntegrationTests`, `AuditVerificationIntegrationTests`) with basic authentication.
  - Implemented `AuditSecurityIntegrationTests` (13 tests) against Testcontainers PostgreSQL 16 verifying unauthenticated 401 with `WWW-Authenticate`, bad credentials 401, cross-role 403, authorized 200/201, unmapped route default deny, and database immutability assertions ensuring rejected requests never modify `audit_event` rows, sequence numbers, or `audit_chain_head`.
  - Implemented `SecurityCredentialValidationTests` (7 tests) verifying fail-fast startup behavior in production mode and safe startup in test/local profiles.
- **Engineer oversight:**
  - Constrained Spring Boot version: prohibited upgrading Spring Boot 3.4.5; added managed Spring Security starters.
  - Mandated stateless HTTP Basic authentication with BCrypt hashing and strict role segregation (`AUDIT_WRITER` cannot query or verify; `AUDITOR` cannot append).
  - Required sanitized JSON error responses matching the existing `ErrorResponse` schema, explicitly preserving `WWW-Authenticate: Basic realm="AuditLogService"` on 401 and omitting it on 403.
  - Mandated external credential sourcing and fail-fast startup validation rejecting empty or default passwords in production mode.
  - Required verification that rejected 401 and 403 requests strictly preserve database invariants (no rows inserted, no sequence or chain-head advancement).
- **Decision:** Approved by the engineer. Committed locally as `d69a172` with message `feat: implement authentication, role authorization, and least privilege access` (local commit; unpushed to `origin`).
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditSecurityIntegrationTests`: 13 tests run, 0 failures, 0 errors, 0 skipped.
    - `SecurityCredentialValidationTests`: 7 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventControllerWebMvcTest`: 18 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventQueryControllerWebMvcTest`: 9 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventVerifyControllerWebMvcTest`: 3 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 145 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.

## 2026-10-15 - Milestone 9 retention, soft archival, and query filtering

- **Task:** Implement Scenario B configurable retention, soft archival (`POST /audit/archive/{eventId}`, `POST /audit/archive/eligible`), Flyway V3 schema migration, default query exclusion (`includeArchived=false`), chain verification preservation, and least-privilege role authorization (`AUDIT_WRITER`).
- **AI contribution:**
  - Authored Flyway migration `V3__add_audit_event_archive.sql` introducing `audit_event_archive` table with PK FK to `audit_event(event_id)`, `archived_at`, `policy_ref`, `archive_location`, index on `archived_at`, and granted `SELECT, INSERT` to application role `audit_app`.
  - Implemented `AuditRetentionProperties` with `@ConfigurationProperties(prefix = "audit.retention")`.
  - Implemented `AuditArchivalService` featuring `@PostConstruct` fail-fast validation in production mode, single event archival (`archive(UUID)`), and batch archival (`archiveEligible()`) with UTC cutoff computed once per batch execution and idempotent insertion (`ON CONFLICT (event_id) DO NOTHING`).
  - Implemented `AuditEventNotFoundException` and registered handler in `AuditControllerAdvice` emitting sanitized HTTP 404 `ErrorResponse`.
  - Implemented `AuditArchivalController` exposing `POST /audit/archive/{eventId}` and `POST /audit/archive/eligible` with correlation IDs and log privacy.
  - Configured role authorization in `SecurityConfiguration` restricting `/audit/archive/**` to role `AUDIT_WRITER`.
  - Updated `AuditQueryService`, `AuditQueryCriteria`, `AuditEventDto`, and `AuditEventController` to support `includeArchived=false` by default via `NOT EXISTS`, and `includeArchived=true` via `LEFT JOIN` exposing `archivedAt`.
  - Implemented MockMvc controller slice tests in `AuditArchivalControllerWebMvcTest` (5 tests).
  - Implemented production configuration validation tests in `AuditRetentionValidationTests` (6 tests).
  - Implemented comprehensive service integration tests in `AuditArchivalServiceIntegrationTests` (9 tests) verifying single-event archival, batch archival, cutoff filtering, idempotency, 404 handling, trigger immutability, hash immutability, full-chain verification integrity, and retention window validation.
  - Added archival security integration tests in `AuditSecurityIntegrationTests` (5 new tests, total 18 tests).
  - Added query archival integration tests in `AuditQueryIntegrationTests` (3 new tests, total 13 tests).
  - Added V3 migration tests in `FlywayMigrationIntegrationTests` (2 new tests, total 17 tests).
  - Added chain verification with archived events test in `AuditVerificationIntegrationTests` (1 new test, total 16 tests).
  - Added query controller slice test in `AuditEventQueryControllerWebMvcTest` (1 new test, total 10 tests).
- **Engineer oversight:**
  - Mandated that `audit_event` rows, hashes, and sequences must remain completely immutable during archival; rejected physical deletion and rejected mutating flags directly on `audit_event`.
  - Enforced separate `audit_event_archive` table with `audit_app` role restricted to `SELECT, INSERT` (no `UPDATE`/`DELETE`).
  - Required configurable retention window with batch cutoff evaluated once per run in UTC.
  - Required fail-fast startup validation for production environments ensuring retention window is explicitly configured and strictly positive.
  - Mandated idempotent behavior (`ON CONFLICT DO NOTHING`) across single and batch archival operations.
  - Restricted archival endpoints to `AUDIT_WRITER` role without inventing unapproved new roles.
  - Verified that `GET /audit/verify` continues to scan and validate 100% of historical events from genesis to chain head without false-positive failures.
  - Verified that query API excludes archived events by default (`includeArchived=false`) and surfaces `archivedAt` only when requested.
- **Decision:** Approved by the engineer. Committed locally as `ba10b37` with message `feat: implement retention policy, soft archival, and query filtering` (local commit; unpushed to `origin`).
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditArchivalControllerWebMvcTest`: 5 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditRetentionValidationTests`: 6 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditArchivalServiceIntegrationTests`: 9 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditSecurityIntegrationTests`: 18 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditQueryIntegrationTests`: 13 tests run, 0 failures, 0 errors, 0 skipped.
    - `FlywayMigrationIntegrationTests`: 17 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditVerificationIntegrationTests`: 16 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventQueryControllerWebMvcTest`: 10 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 177 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.

## 2026-10-15 - Milestone 10 structured payload redaction

- **Task:** Implement Scenario B structured payload redaction while preserving complete-chain cryptographic integrity (`POST /audit/events/{eventId}/redact`), Flyway V4 schema migration, envelope encryption/key destruction (`KeyManager`), redaction metadata table with immutable state triggers, read-time masking projections, `PAYLOAD_REDACTED` meta-audit events, exactly-once pre-append reconciliation discovery, and role authorization (`AUDIT_WRITER`).
- **AI contribution:**
  - Authored Flyway migration `V4__add_audit_event_redaction.sql` creating `audit_event_redaction` table, column-level grants (`SELECT, INSERT`, restricted `UPDATE (status, redacted_at, meta_audit_sequence_no)`), lifecycle state machine trigger `enforce_audit_event_redaction_lifecycle()` sealing `COMPLETED` records, and delete prevention trigger `prevent_audit_event_redaction_delete()`.
  - Implemented `KeyManager` interface and `InMemoryKeyManager` with explicit disclosures of prototype software storage limitations and production KMS migration recommendations.
  - Implemented `EncryptedEnvelope` record and `AuditCryptoService` providing AES-256-GCM authenticated encryption/decryption with 12-byte IV and 128-bit authentication tag, raising typed `KeyDestroyedException` when keys are destroyed.
  - Implemented `AuditRedactionService` orchestrating structured field redaction, JVM-level per-operation locking, idempotency check fast-path, pre-append reconciliation discovery against `audit_event ((payload->>'redactionOperationId'))`, sanitized `PAYLOAD_REDACTED` meta-events omitting plaintext sensitive data, and sealed state updates.
  - Updated `AuditQueryService` to project `"[REDACTED]"` on target field paths of returned events when redaction is completed, leaving database records, content hashes, and record hashes untouched.
  - Updated `SecurityConfiguration` restricting `POST /audit/events/*/redact` to `AUDIT_WRITER`.
  - Added `RedactionKeyDestructionException` handler in `AuditControllerAdvice` mapped to HTTP 502 Bad Gateway.
  - Implemented 6 MockMvc controller slice tests in `AuditRedactionControllerWebMvcTest`.
  - Implemented 5 crypto unit tests in `AuditCryptoServiceTest`.
  - Implemented 8 integration tests in `AuditRedactionServiceIntegrationTests` covering envelope crypto-shredding, legacy plaintext masking, zero plaintext in meta-events, database immutability, full-chain verification integrity, idempotency, reconciliation recovery, concurrent serialization, and KMS failures.
  - Added 3 migration tests in `FlywayMigrationIntegrationTests` (total 20 tests) for V4 schema, column grants, and lifecycle/delete triggers.
  - Added 3 security integration tests in `AuditSecurityIntegrationTests` (total 21 tests) for redaction endpoint authorization.
  - Added query redaction projection test in `AuditQueryIntegrationTests` (total 14 tests).
- **Engineer oversight:**
  - Selected Option A with pluggable `KeyManager` and required explicit disclosure that in-memory key storage is prototype-only, not production-grade cryptographic erasure.
  - Mandated exactly-once logical meta-auditing via durable `redactionOperationId` and pre-append reconciliation discovery to prevent duplicate meta-events upon retry or transient failure.
  - Required database-level enforcement of redaction-state immutability with column-level grants and PostgreSQL triggers sealing `COMPLETED` records against modification or deletion.
  - Mandated that `POST /audit/events/{eventId}/redact` be restricted to `AUDIT_WRITER` and return zero plaintext sensitive values.
  - Enforced that read-time projections mask target field paths without altering stored rows, sequence numbers, or cryptographic commitments (`GET /audit/verify` remains `INTACT`).
- **Decision:** Pending engineer review. Milestone 10 changes uncommitted locally.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditCryptoServiceTest`: 5 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditRedactionControllerWebMvcTest`: 6 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditRedactionServiceIntegrationTests`: 9 tests run, 0 failures, 0 errors, 0 skipped (including multi-transaction concurrency serialized by `SELECT ... FOR UPDATE`).
    - `FlywayMigrationIntegrationTests`: 21 tests run, 0 failures, 0 errors, 0 skipped (including unique constraint rejection on duplicate meta-event operation ID).
    - `AuditSecurityIntegrationTests`: 21 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditQueryIntegrationTests`: 14 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 205 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.
- **Review and Blocker Fixes:**
  - Independent review identified two blockers: (1) `idx_audit_event_meta_redaction_op` was a non-unique index permitting duplicate `PAYLOAD_REDACTED` events; (2) `AuditRedactionService` self-invoked a `@Transactional` method, bypassing Spring's proxy and separating the meta-event append from state finalization.
  - Corrected `idx_audit_event_meta_redaction_op` to `CREATE UNIQUE INDEX` in `V4__add_audit_event_redaction.sql`.
  - Extracted `AuditRedactionCoordinator` as a dedicated Spring `@Component` with an active `@Transactional` boundary, acquiring a pessimistic row lock (`SELECT ... FOR UPDATE`) on `audit_event_redaction` before reconciliation discovery and meta-event append.
  - Added unit/integration tests confirming: (a) PostgreSQL rejects duplicate meta-audit operation IDs with SQLState `23505`; (b) independent concurrent transactions serialize via `SELECT ... FOR UPDATE` and produce exactly one meta-event append; (c) full test suite of 205 tests passes cleanly with 0 regressions.

## Milestone 11: Bulk Export with Independent Verification

- **Task intent:**
  - Satisfy Scenario B bulk export requirement: provide an endpoint to export all records for a given `resourceId` or `actorId` as a self-contained, verifiable bundle with enough chain metadata for a recipient to independently verify records have not been altered since export.
- **AI contribution:**
  - Authored comprehensive architectural design in `docs/milestone11-design.md`, resolving the non-contiguous filtering dilemma via sparse hash-chain witness sequences from genesis ($0^{64}$) to the observed `chainHead`.
  - Explicitly documented critical security and trust boundaries: (a) chain-head checkpoint is an internal point-in-time database commitment, requiring an out-of-band anchor for absolute non-repudiation against superuser history rewriting; (b) sparse chains prove authenticity and tamper-evidence, but cannot prove non-omission of events without disclosing third-party payloads or using zero-knowledge proofs; (c) privacy analysis showing intermediate SHA-256 witness hashes disclose zero sensitive plaintext and are protected against dictionary attacks by high-entropy event metadata (`eventId`, `recordedAt`).
  - Created domain model and versioned DTOs (`bundleVersion: "1.0"`) in `com.example.auditlog.export`: `ExportFilterCriteria`, `ExportFilterDto`, `ExportChainHeadDto`, `ExportSummaryDto`, `ExportEventDto`, `ExportWitnessDto`, `ExportBundleDto`.
  - Implemented `AuditExportService` executing under read-only snapshot transaction (`@Transactional(readOnly = true)`), capturing the chain head, streaming records up to head sequence ordered by `sequence_no ASC`, partitioning into full canonical events and compact witness nodes, populating `archivedAt` for soft-archived records (Milestone 9), and masking legacy plaintext redactions (Milestone 10).
  - Implemented `AuditExportController` (`GET /audit/exports`) with strict validation (mutual exclusivity, non-blank checks, sanitized `ErrorResponse`).
  - Updated `SecurityConfiguration` authorizing `GET /audit/exports` for `AUDITOR` role (HTTP 401 for anonymous, HTTP 403 for `AUDIT_WRITER`).
  - Implemented independent verifiers:
    - Embedded Java verifier `StandaloneExportVerifier` for automated in-process test assertions.
    - Zero-dependency standalone Python verification script `scripts/verify_export.py` using standard library modules only (`hashlib`, `json`, `struct`).
  - Implemented 23 new tests:
    - `AuditExportControllerWebMvcTest` (6 tests): valid `actorId`, valid `resourceId`, mutual exclusivity rejection (HTTP 400), missing filter rejection (HTTP 400), blank filter rejections (HTTP 400).
    - `StandaloneExportVerifierTest` (7 tests): empty chain verification, valid mixed bundle verification, tampered payload detection (`CONTENT_HASH_MISMATCH`), sequence gap detection (`SEQUENCE_GAP`), tampered witness hash detection (`RECORD_HASH_MISMATCH`), tampered chain head detection (`CHAIN_HEAD_MISMATCH`), filter mismatch detection.
    - `AuditExportIntegrationTests` (7 tests): empty database export, export by `actorId` verified by Java and Python script, export by `resourceId`, soft-archival integration (included by default, excluded when `includeArchived=false`), crypto-shredded envelope export with intact ciphertext and accompanying `PAYLOAD_REDACTED` meta-event, legacy masked export, and completeness boundary empirical demonstration.
    - `AuditSecurityIntegrationTests` (3 new tests, 24 total): anonymous rejection (HTTP 401), writer rejection (HTTP 403), auditor authorized (HTTP 200).
- **Engineer oversight:**
  - Approved design decisions: mutually exclusive `actorId` and `resourceId`, default `includeArchived = true`, and genesis-to-head witness chain approach.
  - Mandated explicit documentation of trust boundaries (relative vs. absolute trust anchors, authenticity vs. completeness, privacy of witness hashes, deterministic snapshots).
  - Enforced zero schema migrations (V1–V4 migrations remain untouched) as export is a pure read-only projection.
  - Enforced local-only modification policy with no staging, committing, or pushing until reviewed.
- **Decision:** Milestone 11 implementation complete. Changes uncommitted locally pending engineer review.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - Full Maven test suite: **228 tests run, 0 failures, 0 errors, 0 skipped**.
    - All 205 baseline tests passed with 0 regressions; all 23 new Milestone 11 tests passed cleanly.
  - Python standalone script verification: executed against real export bundles via `ProcessBuilder`, verified exit code 0 and valid output.
  - `git diff --check` passed with 0 errors.

### Hardening pass (Review findings resolution)

- **Legacy masked payload verification**:
  - Distinguished `INTACT` (full content hash recalculation across unredacted and crypto-shredded events) from `PARTIALLY_VERIFIED_REDACTED` (verified chain linkage, sequence contiguity, and record-hash commitments, while explicitly declaring masked original payloads as unverifiable against ingestion content hashes).
  - Synchronized Java verifier (`StandaloneExportVerifier`) and standalone Python script (`scripts/verify_export.py`) to report identical status and counts (`maskedEventsCount` / `maskedEvents`).
  - Added unit and integration tests covering unredacted events, crypto-shredded envelopes, and legacy masked events in both Java and Python verifiers.
- **Consistent database snapshot**:
  - Enforced `Isolation.REPEATABLE_READ` on `@Transactional(readOnly = true)` in `AuditExportService.exportBundle` to guarantee consistent point-in-time PostgreSQL snapshot isolation across the chain-head read, event stream, and redaction metadata queries.
  - Added integration test confirming transactional isolation attributes and consistent snapshot execution.
- **Bounded exports**:
  - Added `AuditExportProperties` with configurable limits: `maxMatchedEvents` (default: 1,000) and `maxTotalRecords` (default: 10,000).
  - Rejection with sanitized HTTP 413 `Payload Too Large` via `PayloadTooLargeException` upon exceeding either limit.
  - Added unit and integration tests for boundary limits and overflow requests.
- **Sequence Range and Exact Occurrence Hardening**:
  - Enforced strict bounds checking `[1, chainHead.sequenceNo]` on all event and witness sequence numbers in both Java (`StandaloneExportVerifier`) and Python (`scripts/verify_export.py`).
  - Enforced duplicate prevention within event collections, within witness collections, and across event/witness boundaries.
  - Enforced exact occurrence and total record count cardinality `len(events) + len(witnesses) == headSeq`.
  - Added 7 focused unit and script parity regression tests in `StandaloneExportVerifierTest`.
- **Validation results**:
  - Full Maven test suite passed: **243 tests run, 0 failures, 0 errors, 0 skipped** across 21 test classes (38 new tests in Milestone 11 over Milestone 10 baseline of 205).
  - `git diff --check` passed cleanly with 0 whitespace errors.
  - Flyway migrations V1–V4 remain strictly untouched.

## 2026-10-15 - Milestone 12 compliance reporting and regulator auditing (Scenario C)

- **Task:** Implement Scenario C: Regulator Auditing of Client Account Data Access in the audit log service.
- **AI contribution:**
  - **Phase 1 & 2 Ambiguity Normalization & Technical Design**:
    - Decomposed under-specified requirement (*"Regulators need to be able to audit access to client account data"*) into explicit assumptions, banking data plane vs. audit plane separation, domain taxonomy, and documented scope boundaries.
    - Drafted initial and refined design artifacts in `scenario-c-design.md`.
  - **Regulator Export Isolation (Server-Side Constrained)**:
    - Blocked `ROLE_REGULATOR` from calling unrestricted `GET /audit/exports` (HTTP 403 Forbidden).
    - Implemented dedicated endpoint `GET /audit/compliance/account-access/export` using `ExportFilterCriteria.forAccount(...)` with server-side forced `requiredResourceType = 'ACCOUNT'`.
    - Ensured exported bundles adhere to `ExportBundleDto` v1.0 and verify out-of-the-box via both `StandaloneExportVerifier` (Java) and `scripts/verify_export.py` (Python 3).
  - **Fail-Closed Supervisory Meta-Auditing**:
    - Designed and implemented `AuditComplianceService` coordinating durable supervisory event appends (`REGULATORY_AUDIT_ACCESSED` and `REGULATORY_EXPORT_ACCESSED`) before data disclosure.
    - Enforced fail-closed behavior: supervisory append failures abort execution immediately, returning sanitized HTTP 503/500 errors with zero account data read or disclosed.
    - Solved supervisory recursion hazard: assigned supervisory events `resourceType = 'COMPLIANCE_AUDIT'` while account queries filter on `resourceType = 'ACCOUNT'`, eliminating query loops and pagination drift while keeping 100% of rows verifiable under `GET /audit/verify`.
  - **Security & Least Privilege**:
    - Added `ROLE_REGULATOR` credentials and fail-fast production startup validation in `SecurityUserProperties` and `SecurityConfiguration`.
    - Enforced strict authorization matrix: regulators can access `/audit/compliance/account-access` and `/export`, but are forbidden (403) from `/audit/events`, `/audit/exports`, `/audit/verify`, and write/archive/redact endpoints.
  - **Test Implementation**:
    - `AuditComplianceControllerWebMvcTest` (7 tests): slice tests covering parameter validation, missing/blank `accountId` (HTTP 400), and fail-closed error translation (HTTP 503/500).
    - `AuditComplianceIntegrationTests` (6 tests): end-to-end Testcontainers PostgreSQL integration covering account and resource-type isolation, supervisory event appends, loop exclusion, soft-archival default inclusion, structured redaction masking, Java/Python export bundle verification, and full-chain verification.
    - `AuditSecurityIntegrationTests` (14 new tests, 38 total): compliance authentication/authorization and regulator least-privilege denials across all operational endpoints.
    - `SecurityCredentialValidationTests` (2 new tests, 9 total): regulator missing username and password production startup validation.
  - **Documentation**: Updated `REQUIREMENTS_AND_DECISIONS.md`, `ARCHITECTURE.md`, `TESTING_AND_BACKLOG.md`, and `AI_USAGE_LOG.md`.
- **Engineer oversight:**
  - Directed design-first workflow with explicit ambiguity normalization and scope boundaries before coding.
  - Mandated server-side constrained export isolation instead of granting regulators access to general `/audit/exports`.
  - Enforced fail-closed supervisory auditing and durable commit sequencing.
  - Required explicit honesty regarding multi-request pagination vs single-request snapshot guarantees.
  - Enforced zero Flyway migrations (V1–V4 preserved untouched) and zero regression on existing milestones.
- **Decision:** Reviewed and approved by the engineer. Committed as `9d42a30` with message `feat: implement regulator account access auditing` and pushed/synchronized to `origin/main`.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - Full Maven test suite: **272 tests run, 0 failures, 0 errors, 0 skipped** across 23 test classes (29 new tests in Milestone 12 over Milestone 11 baseline of 243).
    - All 243 baseline tests passed with 0 regressions.
  - Python standalone script verification: executed against compliance export bundles via `ProcessBuilder`, verified exit code 0 and `Status: INTACT`.
  - `git diff --check` passed cleanly with 0 errors.
  - Flyway migrations V1–V4 remain strictly untouched.

## 2026-10-15 - Milestone 13 final submission readiness audit and documentation remediation

- **Task:** Conduct comprehensive, evidence-based review of repository state against assessment PDF (Version 2.0), verify build/test metrics, identify documentation deliverable gaps, and apply final documentation remediation.
- **AI contribution:**
  - Performed read-only audit of Git repository status, commits, and remote tracking.
  - Extracted requirements, constraints, and deliverables from `Interview_Assignment_Audit_Log_Service.pdf` and generated a traceability matrix.
  - Executed fresh Maven test suite verification (`mvn test`), verifying 272 tests across 23 test classes with 0 failures, 0 errors, and 0 skipped.
  - Identified documentation gaps: unpopulated placeholder in `ATTESTATION.md`, stale Milestone 10 text and missing M11–M12 endpoints/verifier instructions in `README.md`, stale M12 commit status in `AI_USAGE_LOG.md`, and unchecked backlog item 13 in `TESTING_AND_BACKLOG.md`.
  - Applied documentation remediation:
    - Updated `ATTESTATION.md`: populated submission date `2026-10-15` and removed placeholder instructions.
    - Updated `README.md`: updated system overview across Scenarios A, B, and C; documented all endpoints including `/audit/exports`, `/audit/compliance/account-access`, and `/audit/compliance/account-access/export`; documented standalone Python verifier `scripts/verify_export.py`; documented regulator credentials and environment variables; updated test metrics to 272 tests; and documented prototype boundaries and engineering trade-offs.
    - Updated `TESTING_AND_BACKLOG.md`: marked backlog item 13 complete.
- **Engineer oversight:**
  - Mandated read-only review phase before modifying any documentation files.
  - Verified and approved submission date `2026-10-15` in `ATTESTATION.md`.
  - Required accurate documentation of regulator environment variables (`AUDIT_SECURITY_REGULATOR_USERNAME`, `AUDIT_SECURITY_REGULATOR_PASSWORD`) and prototype limitations.
  - Enforced strict documentation-only constraint (no changes to source code, tests, configuration, or Flyway migrations).
  - Reviewed pre-commit working tree status and diffs.
- **Decision:** Reviewed and approved by the engineer. Committed as `f78c17c` with message `docs: complete final submission documentation and attestation` and pushed to `origin/main`.
- **Validation:**
  - `git diff --check` passed cleanly with 0 whitespace errors.
  - Confirmed 0 modifications to Java source files, test files, configuration files, or Flyway migrations V1–V4.
  - `git status --short` verified exactly four modified documentation files: `ATTESTATION.md`, `README.md`, `docs/AI_USAGE_LOG.md`, and `docs/TESTING_AND_BACKLOG.md`.

## 2026-10-15 - Live defense demonstration guide and live environment developer validation

- **Task:** Create comprehensive live defense demonstration guide (`docs/LIVE_DEMO_GUIDE.md`) and document developer live-environment execution and validation across all 8 demonstration phases.
- **AI contribution:**
  - Authored `docs/LIVE_DEMO_GUIDE.md` detailing the 10–15 minute presentation flow, exact curl commands, role requirements, response fields, verbal interview talking points, database trigger bypass commands for live tamper detection, and Q&A defense cheat sheet.
  - Recorded developer live test execution results in `docs/LIVE_DEMO_GUIDE.md` and `docs/TESTING_AND_BACKLOG.md`.
- **Engineer oversight:**
  - Manually started the local PostgreSQL container and Spring Boot application.
  - Executed all 8 demonstration steps live against `http://localhost:8080`:
    1. Event ingestion (`POST /audit/events`, `ROLE_AUDIT_WRITER`, sequence 2).
    2. Filtered querying with stable pagination (`GET /audit/events`, `ROLE_AUDITOR`).
    3. Chain integrity verification (`GET /audit/verify`, `status: INTACT`), live database tampering via superuser update on sequence 2, immediate detection of `status: CORRUPTED` with `CONTENT_HASH_MISMATCH`, and clean restoration.
    4. Soft archival (`POST /audit/archive/{id}`), default query exclusion, explicit inclusion via `includeArchived=true`, and unbroken chain verification (`INTACT`) with zero false positives.
    5. Structured payload redaction (`POST /audit/events/{id}/redact`), automatic append of `PAYLOAD_REDACTED` meta-event, and query projection masking `[REDACTED]`.
    6. Verifiable bulk export (`GET /audit/exports`), and executed standalone standard-library Python verifier `scripts/verify_export.py` reporting `Status: PARTIALLY_VERIFIED_REDACTED` verifying chain linkage while honestly flagging masked payload content.
    7. Compliance query (`GET /audit/compliance/account-access`, `ROLE_REGULATOR`), automatic append of `REGULATORY_AUDIT_ACCESSED` supervisory event, and recursion isolation.
    8. Security negative testing: 401 unauthenticated challenge, 403 regulator role denial on internal logs, and 403 default-deny.
  - Verified and approved documentation updates.
- **Decision:** Changes uncommitted locally pending engineer review.
- **Validation:**
  - `git diff --check` passed cleanly with 0 whitespace errors.
  - Confirmed 0 modifications to application source code, tests, configuration, or Flyway migrations.

## 2026-10-16 - Milestone 14 engineering hardening, rate limiting, idempotency, and CI/CD verification

- **Task:** Implement two-tier token-bucket rate limiting (pre-auth IP limiter and post-auth principal limiter), client idempotency protection with canonical request hashing and chain-head locking, Flyway V5 schema migration, official Apache Maven 3.9.9 wrapper, automated GitHub Actions CI pipeline, and JaCoCo coverage quality gates.
- **AI contribution:**
  - Designed and implemented `TokenBucketRateLimiter` with bounded capacity, per-bucket fine-grained locking, nano-second token replenishment, and atomic eviction.
  - Implemented `PreAuthIpRateLimitingFilter` (100 req/min, burst 20) and `PostAuthPrincipalRateLimitingFilter` (60 req/min, burst 10) emitting sanitized HTTP 429 `ErrorResponse` with `Retry-After: 1`.
  - Authored Flyway migration `V5__add_audit_idempotency.sql` introducing `audit_idempotency_record` table.
  - Implemented client idempotency support via `Idempotency-Key` / `X-Idempotency-Key` headers in `AuditEventController` and `AuditAppendService.appendWithIdempotency()`, using RFC 8785 canonical request hashing and database chain-head locking (`SELECT FOR UPDATE`).
  - Diagnosed and resolved PostgreSQL trigger ordering and transaction boundary failures where `audit_event` insert trigger `trg_audit_chain_head_advance` required head advancement within the same transaction.
  - Resolved Spring MVC mock verification mismatches and payload size / unsafe integer validation error translations.
  - Configured Apache Maven 3.9.9 wrapper (`mvnw`, `mvnw.cmd`, `.mvn/wrapper/maven-wrapper.properties`).
  - Configured GitHub Actions CI pipeline (`.github/workflows/ci.yml`) and Dependabot dependency management (`.github/dependabot.yml`).
  - Configured JaCoCo quality gate rules in `pom.xml` (line 85%, instruction 85%, branch 70%).
  - Added comprehensive test suites: `RateLimitingFilterTest` (15 tests), `RateLimitingSecurityIntegrationTests` (1 test), and updated `AuditSecurityIntegrationTests` (41 tests).
- **Engineer oversight:**
  - Audited and rejected global lock contention in rate limiting; enforced per-bucket fine-grained synchronization with safe eviction.
  - Enforced monotonic clock usage (`System.nanoTime()`) for token replenishment instead of wall-clock time to prevent drift during NTP adjustments.
  - Enforced strict RFC 8785 canonical request hashing for idempotency payload comparison.
  - Verified and corrected transaction sequencing to satisfy the PostgreSQL trigger invariant (`audit_event insert must advance the chain head in the same transaction`).
  - Maintained strict Git branch hygiene: developed and validated on branch `engineering-hardening`, verified remote state, pushed commit `6bce2b3`, and approved merge into `main` as commit `497c7a7`.
- **Decision:** Reviewed and approved by the engineer. Committed as `6bce2b3` on branch `engineering-hardening` and merged into `main` as `497c7a7`.
- **Validation:**
  - Full Maven test suite passed: **304 tests run, 0 failures, 0 errors, 0 skipped** across 25 test classes.
  - JaCoCo coverage verified: **89.91% instruction coverage**, **89.78% line coverage**, and **72.27% branch coverage**, exceeding all configured quality gate thresholds.
  - GitHub Actions CI workflow passed on merge commit `497c7a7` with Testcontainers PostgreSQL 16 and automated artifact generation.
  - `git diff --check` passed cleanly with 0 whitespace errors.
