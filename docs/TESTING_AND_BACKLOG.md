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

## Prioritized backlog

1. [x] Add detailed requirements, architecture, threat model, and acceptance criteria documentation. (Milestone 2)
2. [x] Implement PostgreSQL schema and V1/V2 migration foundations. (Milestone 3)
3. [x] Implement canonicalization and hash components with fixed test vectors. (Milestone 4)
4. [x] Implement transactional append with chain-head locking and persistence tests. (Milestone 4)
5. [x] Implement the event creation REST API (`POST /audit/events`) and validation tests. (Milestone 5)
6. [x] Implement filtered query API (`GET /audit/events`) and stable pagination. (Milestone 6)
7. [ ] Implement complete-chain verification API (`GET /audit/verify`) and direct-database tampering demonstration tests.
8. [ ] Add Spring Security, role authorization (`AUDIT_WRITER`, `AUDITOR`), and security tests.
9. [ ] Implement deferred Scenario B archive-metadata migration, archival workflow, redacted projections, and verifiable export (`GET /audit/exports`).
10. [ ] Finalize Scenario C clarification, selected implementation slice, and scope-boundary evidence.
11. [ ] Add final setup, test, limitation, AI-traceability, attestation, and live-defense documentation.

## Milestone discipline

Before each commit, inspect the exact diff, run the relevant checks, report actual results, propose a commit message, and wait for approval. Record accepted, modified, and rejected AI suggestions with the related validation and commit in `AI_USAGE_LOG.md`.
