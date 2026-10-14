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
- **Decision:** Pending engineer review. Milestone 8 changes uncommitted locally.
- **Validation:**
  - Automated test results under Java 17.0.16 / Maven 3.9.11:
    - `AuditSecurityIntegrationTests`: 13 tests run, 0 failures, 0 errors, 0 skipped.
    - `SecurityCredentialValidationTests`: 7 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventControllerWebMvcTest`: 18 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventQueryControllerWebMvcTest`: 9 tests run, 0 failures, 0 errors, 0 skipped.
    - `AuditEventVerifyControllerWebMvcTest`: 3 tests run, 0 failures, 0 errors, 0 skipped.
    - Full Maven suite: 145 tests run, 0 failures, 0 errors, 0 skipped.
  - `git diff --check` passed with 0 errors.
