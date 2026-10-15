# Audit Log Service

This repository contains a production-grade Java 17 and Spring Boot 3 prototype for the Charles Schwab Audit Log Service engineering assessment.

The service implements an append-only, tamper-evident audit ledger with cryptographic hash chains (RFC 8785 JCS canonicalization and SHA-256), multi-criteria filtering with stable pagination, complete-chain integrity verification, role-based access control, soft archival retention, structured payload redaction (crypto-shredding), self-contained verifiable bulk exports, and regulator auditing of client account access.

## Assessment Scenarios & Milestones

All three assessment scenarios are fully implemented, verified, and committed:

- **Scenario A (Core Audit Log Service)**:
  - Append-only event ingestion (`POST /audit/events`) with 1 MiB body size limits, strict duplicate key rejection, timestamp normalization, and PostgreSQL append-only triggers.
  - Hash-chain integrity with RFC 8785 (JCS) canonical content hashes and length-prefixed domain-separated SHA-256 record hashes.
  - Filtered queries (`GET /audit/events`) by actor, resource, event type, and UTC time range with monotonic pagination by sequence number.
  - Complete-chain verification (`GET /audit/verify`) with streaming cursors and structured violation diagnostics tested against 10 direct-database tampering scenarios.
  - Stateless HTTP Basic authentication with role-based access control (`ROLE_AUDIT_WRITER`, `ROLE_AUDITOR`) and fail-fast production startup credential validation.
- **Scenario B (Retention, Redaction, and Export)**:
  - Configurable retention policy with idempotent single-event and batch soft archival (`POST /audit/archive/{eventId}`, `POST /audit/archive/eligible`), separate metadata table (`audit_event_archive`), zero false-positive verification errors, and default query exclusion (`includeArchived=false`).
  - Structured payload redaction (`POST /audit/events/{eventId}/redact`) via pluggable `KeyManager` and AES-256-GCM envelope crypto-shredding (key destruction), backward-compatible soft-masking for legacy plaintext events, immutable `PAYLOAD_REDACTED` meta-audit events with zero sensitive plaintext disclosure, exactly-once reconciliation discovery, and database-level immutability triggers (`audit_event_redaction`).
  - Self-contained verifiable bulk exports (`GET /audit/exports`) by `actorId` or `resourceId` under repeatable-read snapshot isolation, bounded memory/record limits (HTTP 413), and compact hash witness chains for non-matching records.
  - Dual-verifier independent verification: Java `StandaloneExportVerifier` and zero-dependency Python 3 standard library verifier (`scripts/verify_export.py`).
- **Scenario C (Compliance Reporting & Regulator Auditing)**:
  - Documented ambiguity analysis and normalized requirement: audit plane vs. banking data plane separation, examiner access patterns, and supervisory accountability.
  - Dedicated regulator query API (`GET /audit/compliance/account-access`) with mandatory `accountId`, server-enforced `resourceType = 'ACCOUNT'`, default `includeArchived = true`, and monotonic pagination.
  - Dedicated regulator export API (`GET /audit/compliance/account-access/export`) with server-side forced account scoping and witness generation, independently verifiable via Java and Python verifiers.
  - Fail-closed supervisory meta-auditing: every query and export commits an immutable `REGULATORY_AUDIT_ACCESSED` or `REGULATORY_EXPORT_ACCESSED` event before account data disclosure; append failure immediately aborts with zero data disclosed.
  - Supervisory recursion prevention: supervisory events use `resourceType = 'COMPLIANCE_AUDIT'`, completely isolating them from account queries to prevent feedback loops and pagination drift while keeping 100% of rows verifiable under `GET /audit/verify`.
  - Least-privilege authorization: provisioned `ROLE_REGULATOR` restricted strictly to compliance endpoints, with HTTP 403 Forbidden on general queries, exports, verification, and mutation routes.

## API & Authorization Matrix

| Endpoint | HTTP Method | Role Required | Purpose |
| --- | --- | --- | --- |
| `/audit/events` | `POST` | `ROLE_AUDIT_WRITER` | Ingests append-only audit event (1 MiB limit, strict JSON duplicate-key rejection). |
| `/audit/events` | `GET` | `ROLE_AUDITOR` | Queries events by actor, resource, event type, time range, with pagination. Masks redacted fields as `"[REDACTED]"`. |
| `/audit/verify` | `GET` | `ROLE_AUDITOR` | Walks complete chain from genesis to head; reports `INTACT` or first inconsistency. |
| `/audit/archive/{eventId}` | `POST` | `ROLE_AUDIT_WRITER` | Archives an individual event by ID into separate metadata (idempotent). |
| `/audit/archive/eligible` | `POST` | `ROLE_AUDIT_WRITER` | Batch archives events older than configured retention window ($now - windowDays$). |
| `/audit/events/{eventId}/redact` | `POST` | `ROLE_AUDIT_WRITER` | Redacts payload field (crypto-shreds DEK for envelopes; registers projection mask for legacy). |
| `/audit/exports` | `GET` | `ROLE_AUDITOR` | Exports verifiable bundle filtered by `actorId` or `resourceId` with hash witness chains. |
| `/audit/compliance/account-access` | `GET` | `ROLE_REGULATOR`, `ROLE_AUDITOR` | Queries account access events (`resourceType = 'ACCOUNT'`); commits supervisory audit event. |
| `/audit/compliance/account-access/export` | `GET` | `ROLE_REGULATOR`, `ROLE_AUDITOR` | Exports verifiable bundle scoped strictly to specified account; commits supervisory export event. |

All unmapped routes and unauthorized methods are denied by default (`.anyRequest().denyAll()`). Unauthenticated requests receive a sanitized HTTP 401 `ErrorResponse` with `WWW-Authenticate: Basic realm="AuditLogService"`. Insufficiently privileged requests receive a sanitized HTTP 403 `ErrorResponse` without authentication challenge.

## Prerequisites

- **Java 17 JDK** (tested with Eclipse Adoptium OpenJDK 17.0.16)
- **Maven 3.9+**
- **Docker Desktop** or compatible container runtime for Testcontainers and Compose
- **Python 3.9+** (optional, standard library only, for standalone export bundle verifier)

## Build and Test

Run the full suite of **272 unit and integration tests across 23 test classes**:

```bash
mvn test
```

### Test Suite Structure

The test suite requires zero pre-existing database setup; all database integration tests use isolated, ephemeral Testcontainers PostgreSQL 16 instances:

- **Canonical Hashing & Cryptography (35 tests)**:
  - `AuditHashServiceTest` (29 tests): Hardcoded SHA-256 test vectors verified against external RFC 8785 reference oracles; safe integer boundaries, non-finite float rejection, negative zero normalization.
  - `AuditCryptoServiceTest` (6 tests): AES-256-GCM envelope encryption/decryption, IV handling, authentication tag verification, key destruction, and idempotent destruction.
- **Append & Ingestion (48 tests)**:
  - `AuditEventControllerWebMvcTest` (18 tests): MockMvc slice tests for body size limit (HTTP 413), duplicate key rejection (HTTP 400), invalid types, timestamp parsing, lock contention (HTTP 503 with `Retry-After: 1`), and error sanitization.
  - `AuditAppendServiceIntegrationTests` (18 tests): Genesis append, hash linkage, rollback on trigger failure, and concurrent append serialization against Testcontainers PostgreSQL.
  - `AuditEventControllerIntegrationTests` (7 tests): Full HTTP-to-database integration tests including multi-threaded concurrent appends with contiguous sequence numbers.
  - `AuditAppendConcurrencyIntegrationTests` (3 tests): Application-level concurrent append stress testing.
  - `CanonicalJsonUtilTests` (2 tests): JCS canonicalization utility edge cases.
- **Query & Pagination (24 tests)**:
  - `AuditEventQueryControllerWebMvcTest` (10 tests): MockMvc slice tests for pagination bounds, filter binding, and timestamp range validation.
  - `AuditQueryIntegrationTests` (14 tests): Multi-criteria filter intersection, stable pagination ordering (`sequence_no ASC`), soft-archival inclusion/exclusion, and read-only database invariant assertions.
- **Chain Verification & Tamper Detection (22 tests)**:
  - `AuditEventVerifyControllerWebMvcTest` (6 tests): MockMvc slice tests for intact and corrupted responses.
  - `AuditVerificationIntegrationTests` (16 tests): Full-chain verification against empty chain, single event, multi-event, and 10 specific administrative tampering scenarios (payload alteration, content hash modification, genesis hash change, middle link alteration, record hash modification, middle deletion, first deletion, trailing deletion, chain head modification).
- **Archival & Retention (14 tests)**:
  - `AuditArchivalControllerWebMvcTest` (5 tests): MockMvc slice tests for single and batch archival routes.
  - `AuditArchivalServiceIntegrationTests` (9 tests): Idempotent single/batch archival, cutoff evaluation, hash immutability, and zero false-positive chain verification.
- **Redaction & Crypto-Shredding (25 tests)**:
  - `AuditRedactionControllerWebMvcTest` (8 tests): MockMvc slice tests for redaction requests, parameter validation, and KMS error translation.
  - `AuditRedactionIntegrationTests` (17 tests): Legacy plaintext soft-masking, encrypted envelope crypto-shredding, `PAYLOAD_REDACTED` meta-event append, exactly-once reconciliation discovery, and concurrent redaction serialization.
- **Export Bundles & Independent Verification (53 tests)**:
  - `AuditExportControllerWebMvcTest` (9 tests): MockMvc slice tests for actor/resource mutual exclusivity, validation, and bounded limit rejection (HTTP 413).
  - `AuditExportIntegrationTests` (15 tests): Repeatable-read snapshot consistency, witness generation, soft-archived event inclusion, crypto-shredded envelope retention, and Java/Python verifier execution.
  - `StandaloneExportVerifierTest` (44 tests): Verifier unit tests covering valid bundles, tampered payloads, sequence gaps, witness hash tampering, chain head tampering, filter mismatches, legacy masked bundles (`PARTIALLY_VERIFIED_REDACTED`), sequence range bounds `[1, headSeq]`, duplicate sequence rejection, and Python script parity.
- **Compliance & Regulator Auditing (13 tests)**:
  - `AuditComplianceControllerWebMvcTest` (7 tests): MockMvc slice tests for mandatory `accountId` validation, parameter parsing, and fail-closed error translation (HTTP 503/500).
  - `AuditComplianceIntegrationTests` (6 tests): Account and resource-type isolation, supervisory event append, recursion loop exclusion, soft-archival inclusion, structured redaction masking, Java and Python export verification, and full-chain verification.
- **Security & Authorization (47 tests)**:
  - `AuditSecurityIntegrationTests` (38 tests): Authentication and authorization across writer, auditor, and regulator roles, including 401 unauthenticated, 403 role denials, and default-deny protection.
  - `SecurityCredentialValidationTests` (9 tests): Production startup fail-fast validation for missing, short, or insecure credentials across writer, auditor, and regulator accounts.
- **Database Migrations & Infrastructure (24 tests)**:
  - `FlywayMigrationIntegrationTests` (21 tests): Structural validation of Flyway migrations V1–V4, column types, foreign keys, triggers, and role privilege separation.
  - `AuditLogServiceApplicationTests` (1 test): Spring Boot context loading.
  - `PostgresContainerSanityTests` (1 test): Container sanity check.
  - `ProductionEnvironmentPostgresValidationTests` (1 test): Production configuration sanity check.

## Independent Export Bundle Verification

The repository includes a standalone Python 3 verification script that requires **zero external dependencies** (uses only the Python 3.9+ standard library):

```bash
python3 scripts/verify_export.py <bundle.json>
```

### Verification Checks Performed

1. **Sequence Contiguity & Bounds**: Confirms every sequence from 1 through `chainHead.sequenceNo` exists exactly once without gaps, duplicates, or out-of-range values across combined events and witnesses.
2. **Genesis Linkage**: Confirms sequence 1 references the 64-character all-zero genesis hash.
3. **Previous-Hash Linkage**: Verifies that each record's `previousHash` equals the `recordHash` of the preceding sequence.
4. **Content Hash Recalculation**: For unredacted events and crypto-shredded envelopes, recalculates the RFC 8785 canonical content hash and asserts equality with stored `contentHash`. For legacy masked events, verifies chain commitments without falsely asserting payload matching.
5. **Record Hash Recalculation**: Recalculates domain-separated SHA-256 record hashes (`AUDIT_RECORD_V1` + length-prefixed sequence, previous hash, and content hash) for all records (events + witnesses).
6. **Chain-Head Alignment**: Confirms the final verified record sequence and record hash match the declared `chainHead` checkpoint.
7. **Filter Conformance**: Confirms all exported events match the requested filter criteria.

### Verification Status Outcomes

- `INTACT`: Unbroken chain continuity and 100% cryptographic content hash match across all events.
- `PARTIALLY_VERIFIED_REDACTED`: Unbroken chain continuity and verified hash commitments, with legacy masked records where plaintext was omitted for privacy.
- `CORRUPTED`: Non-zero exit code indicating tampered payload, broken link, sequence gap, duplicate sequence, or invalid chain head.

## Configuration & Credentials

### Environment Variables

Production deployments configure database and role credentials via environment variables:

| Variable | Description | Production Requirement |
| --- | --- | --- |
| `AUDIT_DB_URL` | JDBC URL for application database connection. | Required |
| `AUDIT_DB_USER` | Application database username (limited `audit_app` role). | Required |
| `AUDIT_DB_PASSWORD` | Application database password. | Required |
| `AUDIT_MIGRATOR_DB_URL` | JDBC URL for Flyway migration connection. | Required |
| `AUDIT_MIGRATOR_DB_USER` | Migration database username (owner `audit_migrator` role). | Required |
| `AUDIT_MIGRATOR_DB_PASSWORD` | Migration database password. | Required |
| `AUDIT_SECURITY_WRITER_USERNAME` | Username for `ROLE_AUDIT_WRITER`. | Required, non-empty |
| `AUDIT_SECURITY_WRITER_PASSWORD` | Password for `ROLE_AUDIT_WRITER`. | Required, $\ge 8$ chars, non-default |
| `AUDIT_SECURITY_AUDITOR_USERNAME` | Username for `ROLE_AUDITOR`. | Required, non-empty |
| `AUDIT_SECURITY_AUDITOR_PASSWORD` | Password for `ROLE_AUDITOR`. | Required, $\ge 8$ chars, non-default |
| `AUDIT_SECURITY_REGULATOR_USERNAME` | Username for `ROLE_REGULATOR`. | Required, non-empty |
| `AUDIT_SECURITY_REGULATOR_PASSWORD` | Password for `ROLE_REGULATOR`. | Required, $\ge 8$ chars, non-default |
| `AUDIT_RETENTION_WINDOW_DAYS` | Retention window in days for eligible event archival. | Required, integer $> 0$ |

### Fail-Fast Production Startup Validation

In production mode (non-local, non-test profiles), the service validates configuration during context initialization and immediately aborts startup (`IllegalStateException`) if:
- Any role username or password is missing or blank.
- Any password length is shorter than 8 characters.
- Any password matches known insecure default placeholders (`password`, `changeme`, `secret`, `admin`, `writer-secret`, `auditor-secret`, `regulator-secret`, etc.).
- `audit.retention.window-days` is missing, zero, or negative.

For local development, safe development credentials and a default 90-day retention window are isolated in `src/main/resources/application-local.yaml` under profile `local`.

## Local Development & Docker Compose

Start the local PostgreSQL 16 container:

```bash
docker compose up -d
```

The Compose credentials are for local development only. PostgreSQL defaults to `127.0.0.1:5432`. If port 5432 is occupied by an existing host database, create a git-excluded `compose.override.yaml`:

```yaml
services:
  postgres:
    ports: !override
      - "127.0.0.1:5433:5432"
```

Start the application with the `local` profile to automatically apply Flyway migrations V1–V4:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

When running on an alternate port such as `5433`:

```bash
AUDIT_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
AUDIT_MIGRATOR_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

## Prototype Boundaries & Engineering Trade-offs

1. **Key Management & Crypto-Shredding Boundary**:
   - The prototype uses a pluggable `KeyManager` interface with an in-memory implementation (`InMemoryKeyManager`) for automated test validation.
   - *Limitation*: In-memory keys reside in JVM heap memory and are wiped on process restart. True enterprise crypto-shredding requires master keys residing in a hardware security module (HSM) or managed KMS (e.g. AWS KMS, HashiCorp Vault) whose access logs and lifecycle are independent of database backups and write-ahead logs.
2. **Relative Trust Anchor**:
   - Complete-chain verification (`GET /audit/verify`) and bundle verification use the database chain head or bundle checkpoint as the local trust anchor.
   - *Limitation*: Verification reliably detects accidental corruption, administrative tampering, sequence gaps, payload alterations, and tail deletions relative to the stored database records and chain-head pointer. Detecting complete history rewriting by a database superuser who recalculates all hashes requires an independently trusted external anchor (e.g., periodic external notarization, signed checkpoints, or public ledger anchoring).
3. **Sparse Export Completeness**:
   - Export bundles mathematically prove authenticity, tamper-evidence, and chain inclusion of all exported records without disclosing intermediate third-party payloads.
   - *Limitation*: Sparse exports cannot prove the *non-omission* of matching records without third-party payload disclosure or advanced cryptographic zero-knowledge set-membership proofs.
4. **Supervisory Audit Timing**:
   - In compliance reporting, the supervisory meta-audit event (`REGULATORY_AUDIT_ACCESSED`) is durably committed *prior* to data disclosure to maintain fail-closed data protection.
   - *Behavior*: If the subsequent data query fails, an immutable audit event records that the examination query was initiated, accurately reflecting regulatory supervisory intent.
5. **Data Plane vs. Audit Plane Separation**:
   - The Audit Log Service acts as the authoritative *Audit Plane*. It records access events emitted by upstream banking systems (teller applications, online banking, CRM) via authenticated ingestion. Direct out-of-band queries against upstream business databases that do not emit audit events are outside the service boundary.

## Repository Scope

The confidential assessment PDF remains outside this repository and must not be committed or pushed.
