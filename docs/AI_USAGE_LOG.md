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
