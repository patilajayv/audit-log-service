# Architecture

## Components

| Component | Responsibility |
| --- | --- |
| REST controllers | Validate API requests, map responses, and delegate to application services. |
| Application services | Own append, search, verification, archival, redaction, and export workflows. |
| Crypto & Redaction | Manages DEK lifecycle, AES-256-GCM envelope encryption, crypto-shredding, and read projections. |
| Hash service | Canonicalizes event content and computes SHA-256 hashes. |
| JPA repositories | Persist events and query filters; use a native lock query for the chain head. |
| PostgreSQL | Holds immutable audit events, the chain head, archival metadata, and redaction records. |
| Spring Security | Provides stateless HTTP Basic authentication and endpoint authorization. |

## API contracts

| Endpoint | Contract | Authorization |
| --- | --- | --- |
| `POST /audit/events` | Accepts `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, and optional `sourceTimestamp`; returns `201` with event ID, sequence, server time, and hashes. Enforces a 1 MiB request body limit (HTTP 413) and strict duplicate key detection (HTTP 400). | `AUDIT_WRITER` |
| `GET /audit/events` | Optional `actorId`, `resourceType`, `resourceId`, `eventType`, `from`, `to`, `includeArchived` (default `false`), `page`, `size`; returns a stable sequence-ordered page. When `includeArchived=true`, includes `archivedAt` timestamp. Projected payloads mask completed redacted fields with `"[REDACTED]"` while preserving original cryptographic hashes. | `AUDITOR` |
| `GET /audit/verify` | Verifies the full global chain; returns intact status or first sequence and violation type. Streams all original events regardless of archival or redaction state. | `AUDITOR` |
| `POST /audit/archive/{eventId}` | Archives an individual event by ID. Idempotent (HTTP 200). Returns `ArchiveEventResult`. Returns HTTP 404 if event does not exist. | `AUDIT_WRITER` |
| `POST /audit/archive/eligible` | Batch archives all events recorded before the configured retention cutoff window ($now - windowDays$). Idempotent (HTTP 200). Returns count of newly archived events and cutoff timestamp used. | `AUDIT_WRITER` |
| `POST /audit/events/{eventId}/redact` | Redacts a sensitive field path within an event's payload. For encrypted envelopes, permanently destroys the DEK via `KeyManager.destroyKey` (crypto-shredding); for legacy plaintext, registers soft-masking. Appends an immutable `PAYLOAD_REDACTED` meta-audit event with zero sensitive plaintext. Idempotent with reconciliation discovery on retry. Returns `RedactionResult`. | `AUDIT_WRITER` |
| `GET /audit/exports` | Scenario B endpoint. Requires exactly one of `actorId` or `resourceId`; returns a verifiable bundle. Restricted to internal auditors. | `AUDITOR` |
| `GET /audit/compliance/account-access` | Scenario C endpoint. Requires `accountId`; filters strictly on `resourceType = 'ACCOUNT'`; defaults `includeArchived = true`. Commits fail-closed supervisory `REGULATORY_AUDIT_ACCESSED` event. | `REGULATOR`, `AUDITOR` |
| `GET /audit/compliance/account-access/export` | Scenario C endpoint. Dedicated, server-side constrained export strictly for `resourceType = 'ACCOUNT'`. Commits fail-closed supervisory `REGULATORY_EXPORT_ACCESSED` event; returns independently verifiable bundle. | `REGULATOR`, `AUDITOR` |

No `PUT`, `PATCH`, or `DELETE` audit-event endpoint will exist. Unauthenticated requests receive `401`; authenticated callers without the required role receive `403`.

### Write API protocol (`POST /audit/events`)

The write API is implemented by `AuditEventController` and protected by defensive servlet-level filters, rate limiters, and controller-advice exception mappers:

1. **Size enforcement (`RequestBodySizeLimitFilter`)**: Registered with `HIGHEST_PRECEDENCE`. Evaluates declared `Content-Length` and wraps chunked/streaming input streams with a byte counter. Bodies exceeding 1 MiB (1,048,576 bytes) are aborted with HTTP 413 before deserialization or append invocation.
2. **Pre-authentication IP rate limiting (`PreAuthIpRateLimitingFilter`)**: Intercepts requests prior to authentication challenge. Enforces a token-bucket allowance (default: 100 req/min, burst 20). Excess requests are aborted with sanitized HTTP 429 `Too Many Requests` and a `Retry-After: 1` header.
3. **Authentication & authorization (`SecurityConfiguration`)**: Stateless HTTP Basic authentication verifies credentials against `BCryptPasswordEncoder`. Requires `ROLE_AUDIT_WRITER` (401 unauthenticated, 403 insufficient role).
4. **Post-authentication principal rate limiting (`PostAuthPrincipalRateLimitingFilter`)**: Enforces per-principal metering (default: 60 req/min, burst 10) to prevent authorized credential abuse. Throttled callers receive sanitized HTTP 429 with `Retry-After: 1`.
5. **Strict duplicate key detection**: Configured globally in Jackson (`JsonParser.Feature.STRICT_DUPLICATE_DETECTION`). Requests with duplicate JSON keys at the root level or within nested `payload` objects are rejected with HTTP 400.
6. **Payload validation**: Null or non-object payloads and integers outside safe IEEE-754 range $[-(2^{53}-1), 2^{53}-1]$ are rejected with HTTP 400.
7. **Timestamp normalization**: Omitted timestamps default to `null`. Offset-bearing timestamps (e.g. `+02:00`) are parsed to UTC `Instant` and normalized to millisecond precision (`ChronoUnit.MILLIS`).
8. **Client idempotency evaluation (`AuditAppendService.appendWithIdempotency`)**:
   - Evaluates optional `Idempotency-Key` or `X-Idempotency-Key` header (UUID format, max 128 chars).
   - Computes an RFC 8785 canonical SHA-256 request hash over `{actorId, eventType, payload, resourceId, resourceType, sourceTimestamp}`.
   - Executes under database transaction with chain-head row locking (`SELECT FOR UPDATE FROM audit_chain_head WHERE chain_id = 1`):
     - If `(client_id, idempotency_key)` exists in `audit_idempotency_key` and stored `request_hash` matches: returns original `AuditEventResponse` with HTTP 200 OK.
     - If `(client_id, idempotency_key)` exists with a different `request_hash`: throws `IdempotencyConflictException`, mapped by `AuditControllerAdvice` to sanitized HTTP 409 Conflict.
     - If key does not exist: inserts into `audit_event`, updates `audit_chain_head`, and records the key in `audit_idempotency_key` atomically in the same transaction, satisfying the PostgreSQL trigger invariant (`trg_audit_chain_head_advance`) and returning HTTP 201 Created.
9. **Delegation without idempotency**: If no idempotency header is supplied, delegates directly to transactional `AuditAppendService.append(request)` (locks chain head, inserts event, advances head, returns HTTP 201).
10. **Error handling and sanitization (`AuditControllerAdvice`)**: Maps handled exception categories to appropriate HTTP status codes: client syntax and validation failures (`MethodArgumentNotValidException`, `HttpMessageNotReadableException`, `IllegalArgumentException`) to HTTP 400; not found errors (`AuditEventNotFoundException`) to HTTP 404; idempotency conflict (`IdempotencyConflictException`) to HTTP 409; body size limit exceedance (`PayloadTooLargeException`) to HTTP 413; media type mismatches (`HttpMediaTypeNotSupportedException`) to HTTP 415; unsupported methods (`HttpRequestMethodNotSupportedException`) to HTTP 405; rate limiting throttles to HTTP 429; and chain-head lock contention (`CannotAcquireLockException`, `PessimisticLockingFailureException`, `QueryTimeoutException`) to HTTP 503 with a `Retry-After: 1` header. For database failures (`DataAccessException`, `SQLException`) and unexpected errors (`Exception`), it emits sanitized generic HTTP 500 responses (`"An internal database error occurred while recording the audit event."` or `"An internal error occurred while processing the audit event."`), actively suppressing SQL syntax, table names, constraint details, and stack traces. Operational logs record correlation IDs, `eventId`, and `sequenceNo`, while omitting sensitive event `payload`, `actorId`, and `resourceId` values.

## Data model

### `audit_event`

| Column | Purpose |
| --- | --- |
| `sequence_no` | `BIGINT` primary key; global chain order starting at 1. |
| `event_id` | Unique UUID exposed to clients. |
| `event_type`, `actor_id`, `resource_type`, `resource_id` | Required event identity and subject fields. |
| `payload` | Required JSONB value, potentially containing encrypted envelopes. |
| `source_timestamp` | Optional caller-supplied UTC timestamp. |
| `recorded_at` | Required service-assigned UTC timestamp. |
| `canonicalization_version` | Required value, initially `JCS-1`. |
| `content_hash`, `previous_hash`, `record_hash` | Required lowercase hexadecimal SHA-256 values. |

Indexes support `actor_id`, `(resource_type, resource_id)`, `event_type`, `recorded_at`, and sequence pagination. Unique constraints protect `event_id` and `sequence_no`.

### `audit_chain_head`

One row for the global chain stores `last_sequence_no` and `last_record_hash`. It is locked during each append and compared after full-chain verification.

### `audit_event_archive`

Scenario B archival metadata keyed by `event_id` (Flyway `V3__add_audit_event_archive.sql`).

| Column | Type | Purpose |
| --- | --- | --- |
| `event_id` | `UUID PRIMARY KEY` | References `audit_event(event_id)` via foreign key constraint. |
| `archived_at` | `TIMESTAMPTZ NOT NULL` | Service-assigned UTC timestamp when the record was archived. |
| `policy_ref` | `VARCHAR(128) NOT NULL` | Identifier of retention policy rule applied (e.g., `RETENTION_WINDOW_DAYS`). |
| `archive_location` | `VARCHAR(256)` | Optional reference or URI to cold storage/external archive destination. |

Index on `archived_at` accelerates time-based archival queries and pruning.
The table is owned by `audit_migrator`, and the application role `audit_app` is granted `SELECT, INSERT` (no `UPDATE` or `DELETE`).
Archiving records into this table never alters or mutates rows in `audit_event`, preserving all cryptographic hashes, sequences, and chain links.

### `audit_event_redaction`

Scenario B structured payload redaction metadata and lifecycle enforcement (Flyway `V4__add_audit_event_redaction.sql`).

| Column | Type | Purpose |
| --- | --- | --- |
| `redaction_id` | `BIGSERIAL PRIMARY KEY` | Internal autoincrementing surrogate identifier. |
| `operation_id` | `VARCHAR(256) UNIQUE NOT NULL` | Deterministic operation identifier (`"redact:" + event_id + ":" + field_path`) guaranteeing deduplication. |
| `event_id` | `UUID NOT NULL` | References `audit_event(event_id)` with `ON DELETE RESTRICT`. |
| `field_path` | `VARCHAR(256) NOT NULL` | Dot-delimited JSON property path targeted for redaction (e.g. `accountNumber`, `tax.id`). |
| `redacted_at` | `TIMESTAMPTZ NOT NULL` | UTC timestamp when the redaction reached `COMPLETED`. |
| `reason` | `VARCHAR(128) NOT NULL` | Business/regulatory reason for redaction (e.g., `GDPR_ARTICLE_17`, `CCPA_ERASURE`). |
| `requested_by` | `VARCHAR(128) NOT NULL` | User or automated actor identity requesting redaction. |
| `redaction_type` | `VARCHAR(32) NOT NULL` | `CRYPTO_SHREDDED` (key destroyed for encrypted envelope) or `MASKED` (projection-masked legacy event). |
| `status` | `VARCHAR(32) NOT NULL` | State machine: `PENDING` $\rightarrow$ `KEY_DESTRUCTION_FAILED` $\vert$ `KEY_DESTROYED` $\rightarrow$ `COMPLETED`. |
| `key_id` | `VARCHAR(256)` | Key identifier destroyed in `KeyManager` (null for legacy plaintext events). |
| `meta_audit_sequence_no` | `BIGINT` | Sequence number of the immutable `PAYLOAD_REDACTED` event appended to `audit_event`. |

Indexes support `event_id`, `redacted_at`, and `status`. A partial index on `audit_event ((payload->>'redactionOperationId')) WHERE event_type = 'PAYLOAD_REDACTED'` accelerates pre-append reconciliation discovery.
The table is owned by `audit_migrator`. The application role `audit_app` is granted narrow column privileges: `SELECT, INSERT` on all columns, and `UPDATE (status, redacted_at, meta_audit_sequence_no)` only. Any attempt by `audit_app` to mutate immutable metadata columns (`reason`, `requested_by`, `field_path`, `event_id`, etc.) is blocked by PostgreSQL's permission model (`42501 permission denied`).
Furthermore, `trg_audit_event_redaction_lifecycle` permanently seals completed records (disallowing any mutation once `COMPLETED`), validates monotonic state transitions, and enforces a non-null `meta_audit_sequence_no` before transitioning to `COMPLETED`. A delete trigger (`trg_audit_event_redaction_no_delete`) blocks `DELETE` and `TRUNCATE` operations even for administrative roles.

### `audit_idempotency_key`

Milestone 14 client idempotency tracking keyed by `(client_id, idempotency_key)` (Flyway `V5__add_audit_idempotency.sql`).

| Column | Type | Purpose |
| --- | --- | --- |
| `idempotency_key` | `VARCHAR(256) NOT NULL` | Client-supplied unique transaction/request identifier. |
| `client_id` | `VARCHAR(128) NOT NULL` | Authenticated principal name scoping the idempotency namespace. |
| `request_hash` | `VARCHAR(64) NOT NULL` | RFC 8785 canonical SHA-256 hash of the append request payload. |
| `event_id` | `UUID NOT NULL` | References `audit_event(event_id)` with `ON DELETE RESTRICT`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | Service-assigned UTC timestamp when the key was recorded. |

Primary key is `(client_id, idempotency_key)`. An index on `created_at` supports TTL expiration and pruning.
The table is owned by `audit_migrator`. The application role `audit_app` is granted `SELECT, INSERT` privileges only (no `UPDATE`, `DELETE`, or `TRUNCATE`).
Rows in `audit_idempotency_key` are inserted atomically with `audit_event` and `audit_chain_head` advancement under a single transaction.

## Hash chain

### Canonical event content

`content_hash` is `SHA-256` of UTF-8 RFC 8785 JSON Canonicalization Scheme (JCS) content with this exact shape:

```json
{
  "actorId": "actor-123",
  "canonicalizationVersion": "JCS-1",
  "eventId": "00000000-0000-0000-0000-000000000001",
  "eventType": "USER_LOGIN",
  "payload": { "canonical": "json" },
  "recordedAt": "2026-10-14T15:00:01.456Z",
  "resourceId": "account-456",
  "resourceType": "ACCOUNT",
  "sourceTimestamp": "2026-10-14T15:00:00.123Z"
}
```

Top-level object keys are sorted lexicographically by UTF-16 code units per RFC 8785 §3.2.3. Canonicalization is performed using `io.github.erdtman:java-json-canonicalization:1.1`, which implements ECMAScript 6 §7.1.12.1 number serialization, -0.0 normalization to 0, integer-valued float normalization without decimal points, scientific notation, and control-character escaping (`\\u00xx`).

Optional `sourceTimestamp` is represented as JSON `null` when absent. All timestamps use UTC with millisecond precision (`yyyy-MM-dd'T'HH:mm:ss.SSS'Z'`) and are truncated to milliseconds (`ChronoUnit.MILLIS`) upon request ingestion.

#### Numeric policy (RFC 8785 Appendix D & RFC 7493 §2.2)

- **Safe integers**: Integers within $[-(2^{53} - 1), 2^{53} - 1]$ ($[-9007199254740991, 9007199254740991]$) are serialized as exact JSON numbers without precision loss.
- **Unsafe integers**: Integers outside this range (including signed 64-bit boundaries like `Long.MAX_VALUE`, `Long.MIN_VALUE`, and arbitrary-precision `BigInteger`) are rejected with `IllegalArgumentException` to prevent silent IEEE-754 precision loss.
- **Exact large values**: Callers requiring exact representation of 64-bit integers or arbitrary decimals must encode them as JSON strings.
- **Non-finite numbers**: `NaN`, `Infinity`, and overflowing decimals are rejected.
- **Duplicate keys**: Rejected by both `JsonCanonicalizer` (`IOException`) and Jackson `ObjectMapper` strict duplicate detection.

#### Record hash

The first event uses the 64-character lowercase-zero genesis hash. Each `record_hash` is SHA-256 over four length-prefixed UTF-8 components in this exact order:

1. `AUDIT_RECORD_V1` (domain separator)
2. `sequence_no` (decimal string, e.g. `"1"`)
3. `previous_hash` (64-character lowercase hex)
4. `content_hash` (64-character lowercase hex)

Each component is prefixed by its 4-byte big-endian unsigned length in bytes, eliminating any field-boundary ambiguity.

### Append transaction and concurrency

The `AuditAppendService` runs one transaction:

1. Lock the singleton chain-head row with `SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1 FOR UPDATE`.
2. Derive the next sequence (`last_sequence_no + 1`) and previous hash (`last_record_hash`).
3. Truncate timestamps to milliseconds, canonicalize event content per RFC 8785, and compute `content_hash` and `record_hash`.
4. Insert the new event into `audit_event`.
5. Update `audit_chain_head` with the new sequence and record hash.
6. Commit both writes together.

The head-row lock serializes concurrent writers. A failed insert, hash computation, or head update rolls back the whole transaction. Application-level concurrency has been verified in integration tests (`concurrentAppendsProduceTwoSequentialEventsWithNoGaps()`): concurrent appends serialize on the row lock and commit distinct contiguous sequence numbers without gaps or duplicate sequences.

Database triggers provide defense in depth for the same ordering. The insert trigger locks the chain head and accepts only the next sequence with the current head hash as `previous_hash`. The head-update trigger then requires that inserted event to have the new head sequence and hash. A deferred constraint trigger rejects a transaction that inserts an event without advancing the head to it.

The chain-head linkage protection is delivered as a forward-only Flyway `V2` migration. Fresh databases apply `V1` followed by `V2`; databases that already recorded `V1` retain their migration history and receive `V2` on the next Flyway run.

### Query API and pagination

The `AuditQueryService` provides read-only querying of committed audit events via `GET /audit/events`:

1. **Filtering**: Supports filtering by any combination of `actorId`, `resourceType`, `resourceId`, `eventType`, and time range (`from` and `to` against service-assigned `recorded_at`). All user-supplied criteria are bound strictly using parameterized SQL placeholders (`?`) across both count and data queries.
2. **Pagination and ordering**: Pagination parameters (`page` with default 0, `size` with default 20, max 100) are validated. Queries execute with `ORDER BY sequence_no ASC LIMIT ? OFFSET ?`, guaranteeing deterministic, monotonic ordering by sequence number.
3. **Consistency model**: Under PostgreSQL's default `READ COMMITTED` transaction isolation, each HTTP request executes in its own independent database transaction. Ordering by `sequence_no ASC` provides deterministic results for already-committed events. However, separate HTTP requests do not share a database transaction snapshot across pages; concurrent appends committed between page requests will increment `totalElements` and advance the chain head without altering the ordering of already-committed sequences.
4. **Read-only enforcement**: The service operates under `@Transactional(readOnly = true)`. Queries never insert, update, or delete rows, and never advance sequence numbers or the chain head.
5. **Privacy and security**: Request logging records only correlation IDs; sensitive query parameters (e.g., `actorId`, `resourceId`) and audit event payloads are never logged. Authentication and role-based access control (`AUDITOR` role) are operational requirements for production deployment and are scheduled for Milestone 8.

### Verification behavior

The `AuditVerificationService` exposes complete-chain verification via `GET /audit/verify`:

1. **Algorithm and checks**:
   - Reads the singleton `audit_chain_head` row (`chain_id = 1`).
   - If `audit_chain_head` is missing, reports `CHAIN_HEAD_MISMATCH` with diagnostic details rather than a generic database error.
   - For an empty chain (`last_sequence_no = 0`), confirms genesis hash and verifies that zero rows exist in `audit_event`.
   - For non-empty chains, streams records ordered by `sequence_no ASC` using PostgreSQL cursor-based streaming (`fetchSize = 500`) inside a read-only transaction (`@Transactional(readOnly = true)`).
   - Validates sequence contiguity (`sequence_no = expected_sequence`), genesis previous-hash (`sequence 1` uses 64 all-zero genesis hash), previous-hash linkage (`sequence N` points to record hash of `sequence N-1`), recomputes RFC 8785 canonical content hash, recomputes domain-separated record hash, and stops immediately upon the first violation.
   - Compares the final verified record sequence and record hash against the declared `audit_chain_head` state.

2. **Response semantics**:
   - Returns HTTP 200 OK with `AuditVerificationResponse` distinguishing stored chain-head metadata from verified values:
     - `status`: `"INTACT"` or `"CORRUPTED"`.
     - `recordsVerified`: number of records sequentially scanned and cryptographically validated.
     - `headSequenceNo`: sequence number stored in `audit_chain_head` (null if head row missing).
     - `headRecordHash`: record hash stored in `audit_chain_head` (null if head row missing).
     - `lastVerifiedSequenceNo`: sequence number of the last successfully verified record (0 for empty chain).
     - `lastVerifiedRecordHash`: record hash of the last successfully verified record (genesis for empty chain).
     - `violation`: structured `ChainViolation` object detailing `type`, `sequenceNo`, `eventId`, `expected`, `actual`, and sanitized `message` (null if intact).

3. **Violation categories**:
   - `GENESIS_MISMATCH`: First event does not use the 64-character all-zero genesis hash.
   - `SEQUENCE_GAP`: Sequence numbers are non-contiguous or do not start at 1 (detects missing intermediate rows, missing initial row, or reordered rows).
   - `CONTENT_HASH_MISMATCH`: Stored `content_hash` does not match recomputed RFC 8785 canonical content hash (detects modified payloads or metadata).
   - `PREVIOUS_HASH_MISMATCH`: Event `previous_hash` does not match the preceding event's `record_hash` (detects broken hash pointers).
   - `RECORD_HASH_MISMATCH`: Stored `record_hash` does not match recomputed record hash.
   - `CHAIN_HEAD_MISMATCH`: Missing `audit_chain_head` row, or head sequence/hash does not match the tail of the verified event chain (detects trailing truncation or phantom head updates).

4. **Trust and security boundary**:
   - Verification reliably detects accidental corruption, administrative tampering, sequence gaps, payload alterations, and tail deletions relative to the stored database records and chain-head pointer.
   - *Security limitation*: Verification relies on the local database's chain head as the local trust anchor. An attacker possessing full administrative access who rewrites the entire chain from genesis and recalculates valid hashes and a matching chain head cannot be detected by internal database verification alone without an independently trusted external anchor (such as signed external checkpoints, witness logs, or external timestamping).

## Append-only controls

The normal application database role receives only the minimum `SELECT` and `INSERT` rights for audit events. Migration and administrative identities are separate. PostgreSQL triggers reject `UPDATE`, `DELETE`, and `TRUNCATE` against `audit_event`; normal application APIs expose no mutation routes.

For local development, Docker Compose starts PostgreSQL 16 as `audit_migrator` and bootstraps the limited `audit_app` role. Flyway runs with the migrator identity; the application uses `audit_app`. PostgreSQL is bound to the loopback interface (`127.0.0.1:5432`, or `127.0.0.1:5433` via local override when port 5432 is occupied by an existing host database). Operational environments must provision equivalent roles before migration. These controls prevent accidental application mutations, but schema owners and superusers can change permissions, disable triggers, or rewrite data.

The required tampering demonstration uses a separately authorized administrative connection in a documented test procedure. It temporarily bypasses the protection or uses a maintenance-only path to alter a row, then calls the ordinary verification API. The application role never receives update or delete rights.

## Security

The service implements stateless HTTP Basic authentication and role-based access control using Spring Security:

1. **Session and CSRF management**: Operates strictly in stateless mode (`SessionCreationPolicy.STATELESS`). CSRF protection is disabled (`AbstractHttpConfigurer::disable`) because the API relies on stateless HTTP Basic authorization headers rather than browser cookie-based sessions.
2. **Password encoding**: All user passwords are encrypted using `BCryptPasswordEncoder`.
3. **Role-based authorization and default deny**:
   - `POST /audit/events`: requires role `AUDIT_WRITER`
   - `POST /audit/archive/{eventId}`: requires role `AUDIT_WRITER`
   - `POST /audit/archive/eligible`: requires role `AUDIT_WRITER`
   - `GET /audit/events`: requires role `AUDITOR`
   - `GET /audit/verify`: requires role `AUDITOR`
   - All other routes are denied by default via `.anyRequest().denyAll()`.
4. **Sanitized error handling**:
   - **401 Unauthorized**: Handled by `RestAuthenticationEntryPoint`. Emits a sanitized JSON `ErrorResponse(401, "Unauthorized", "Full authentication is required to access this resource", timestamp)` and preserves the standard `WWW-Authenticate: Basic realm="AuditLogService"` header.
   - **403 Forbidden**: Handled by `RestAccessDeniedHandler`. Emits a sanitized JSON `ErrorResponse(403, "Forbidden", "Access is denied: insufficient role privileges", timestamp)` without disclosure of internal security rules or stack traces, and omits the `WWW-Authenticate` header.
5. **External credential configuration and fail-fast startup validation**:
   - Configured via `SecurityUserProperties` mapped from `audit.security.writer.*` and `audit.security.auditor.*`.
   - **Production mode**: In non-local, non-test environments, application startup performs strict fail-fast validation. If either username or password is missing/blank, password length is under 8 characters, or passwords match known insecure default placeholders (`password`, `changeme`, `admin`, `secret`, `writer-secret`, `auditor-secret`, etc.), context initialization throws an `IllegalStateException` and aborts startup.
   - **Local development mode**: Isolated to the `local` profile in `application-local.yaml`.
   - **Test mode**: Provided with dedicated, non-production test credentials in `src/test/resources/application.yaml`.
6. **Database immutability invariant**:
   - Requests rejected with HTTP 401 or HTTP 403 are intercepted before controller or database layer execution, guaranteeing that unauthenticated and unauthorized requests never modify `audit_event` rows, sequence numbers, or `audit_chain_head` state.

| Role | Allowed operations | Prohibited operations |
| --- | --- | --- |
| `AUDIT_WRITER` | Create audit events (`POST /audit/events`), archive audit events (`POST /audit/archive/{eventId}`, `POST /audit/archive/eligible`), redact audit events (`POST /audit/events/{eventId}/redact`). | Query events (`GET /audit/events`), verify chain (`GET /audit/verify`). |
| `AUDITOR` | Query events (`GET /audit/events`), verify chain (`GET /audit/verify`), export records. | Create audit events (`POST /audit/events`), archive events (`POST /audit/archive/**`), redact events (`POST /audit/events/*/redact`). |

Production controls would add centralized identity (OIDC/OAuth2/mTLS), short-lived token issuance, secret management (Vault/AWS Secrets Manager), network policy restrictions, auditing of privileged database access, and separate operational roles.

## Retention, archival, redaction, and export

### Retention and archival implementation

1. **Retention policy configuration**:
   - Configured via `audit.retention.window-days` (bound to `AuditRetentionProperties`).
   - Defaults to 90 days in local profile (`application-local.yaml`) and 30 days in test profile (`src/test/resources/application.yaml`).
   - In production environments, `@PostConstruct` fail-fast validation ensures `audit.retention.window-days` is explicitly configured and strictly positive ($> 0$), aborting context startup with `IllegalStateException` if missing, non-positive, or unconfigured.

2. **Batch cutoff evaluation**:
   - Batch archival computes a single UTC cutoff timestamp once per batch execution: `cutoff = Instant.now().minus(windowDays, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS)`.
   - All events with `recorded_at < cutoff` that lack an entry in `audit_event_archive` are archived atomically.

3. **Atomic, idempotent operations**:
   - `POST /audit/archive/{eventId}`: Archives an individual event by ID. Inserts into `audit_event_archive` with `ON CONFLICT (event_id) DO NOTHING`. Returns `archived: true` if newly archived, or `archived: false` (with original `archivedAt`) if already archived. Throws `AuditEventNotFoundException` (mapped to sanitized HTTP 404 `ErrorResponse`) if the event ID does not exist in `audit_event`.
   - `POST /audit/archive/eligible`: Batch archives all eligible records older than the retention cutoff. Uses `INSERT INTO audit_event_archive ... SELECT ... WHERE recorded_at < ? ON CONFLICT (event_id) DO NOTHING`. Returns count of newly archived records and batch cutoff timestamp.

4. **Chain verification preservation**:
   - `GET /audit/verify` streams all records directly from `audit_event ORDER BY sequence_no ASC` without filtering by archive state.
   - Archiving records never updates, deletes, or alters `audit_event` rows, sequence numbers, or `audit_chain_head`. Verification continues to cryptographically validate 100% of historical events from genesis to chain head with zero false-positive failures.

5. **Query behavior**:
   - `GET /audit/events` excludes archived records by default using `WHERE NOT EXISTS (SELECT 1 FROM audit_event_archive a WHERE a.event_id = e.event_id)`.
   - When callers specify `includeArchived=true`, queries include both active and archived records via `LEFT JOIN audit_event_archive a ON a.event_id = e.event_id`, populating `archivedAt` on returned `AuditEventDto` objects.

### Structured payload redaction implementation (Scenario B)

1. **Cryptographic Invariants & Dual-Tier Verification**:
   - Direct in-place mutation of `audit_event.payload` would invalidate `content_hash`, `record_hash`, and all subsequent hashes through to `audit_chain_head`.
   - The physical row in `audit_event` is **never updated or deleted**. `prevent_audit_event_mutation` triggers remain strictly enforced.
   - `GET /audit/verify` operates on the physical ledger rows and reports `status: "INTACT"` (0 false positives).
   - `GET /audit/events` queries `audit_event_redaction` for completed redactions and projects a masked payload (`"[REDACTED]"` for target field paths) while preserving the original immutable hashes (`contentHash`, `recordHash`).

2. **Backward Compatibility & Ingestion Model**:
   - **Category 1 (Legacy Plaintext Events)**: For events ingested without field encryption, redaction records `redaction_type = 'MASKED'` and applies presentation-layer masking on query projections. Original plaintext remains in the append-only ledger row, satisfying projection masking without physical erasure.
   - **Category 2 (Encrypted Envelope Events)**: Sensitive fields are ingested wrapped in an `EncryptedEnvelope` (`algorithm: "AES-256-GCM"`, `keyId`, `ciphertext`, `iv`, `keyScope: "EVENT_FIELD"`). Redaction permanently destroys the DEK via `KeyManager.destroyKey(keyId)` and records `redaction_type = 'CRYPTO_SHREDDED'`. Once the DEK is destroyed, the stored ciphertext is mathematically indecipherable ($2^{256}$ keyspace), achieving cryptographic erasure (crypto-shredding) while keeping the stored ciphertext, `content_hash`, and chain continuity 100% intact.

3. **Pluggable `KeyManager` Interface**:
   - `KeyManager` interface provides `generateKey(keyId)`, `getKey(keyId)`, `destroyKey(keyId)`, `isKeyActive(keyId)`, and `isKeyDestroyed(keyId)`.
   - Default implementation `InMemoryKeyManager` is software-backed for prototype validation and automated testing.
   - **Explicit Prototype Limitations**: In-memory keys are volatile and wiped on process restart; keys reside in JVM heap memory without hardware tamper resistance; storage is process-local and does not scale across clustered nodes; true production crypto-shredding requires master keys in an HSM or managed KMS (AWS KMS, HashiCorp Vault) whose lifecycle is independent of database backups and WAL archives.

4. **Exactly-Once Logical Meta-Auditing, Transaction Boundaries & Reconciliation**:
   - Every completed redaction appends an immutable `PAYLOAD_REDACTED` event to the chain, capturing coordinate metadata (`redactionOperationId`, `targetEventId`, `targetSequenceNo`, `fieldPath`, `reason`, `redactionType`, `keyId`) with **zero sensitive plaintext**.
   - A deterministic `operation_id = "redact:" + event_id + ":" + field_path` ensures deduplication.
   - Database uniqueness is strictly enforced by partial unique index `idx_audit_event_meta_redaction_op` on `audit_event ((payload->>'redactionOperationId')) WHERE event_type = 'PAYLOAD_REDACTED'`. Any attempt to insert a duplicate meta-event is rejected at the database engine level with SQLState `23505`.
   - Transaction boundaries are managed via dedicated Spring collaborator `AuditRedactionCoordinator`. Before reconciliation discovery or meta-audit append, it acquires a pessimistic row lock with `SELECT ... FOR UPDATE` on `audit_event_redaction WHERE operation_id = ?`, holding the lock throughout the transaction.
   - If another node or thread completes the operation while waiting on the row lock, the coordinator discovers the completed status and returns immediately without appending a duplicate.
   - Pre-append reconciliation queries `audit_event` for an already-appended meta-event with `payload->>'redactionOperationId' = ?`. If discovered, the service links the existing sequence number to `audit_event_redaction.meta_audit_sequence_no` without appending a duplicate meta-event.

5. **Database Enforcement of Immutability**:
   - `audit_app` is granted narrow column privileges: `SELECT, INSERT` on all columns, `UPDATE (status, redacted_at, meta_audit_sequence_no)` only, and `USAGE, SELECT` on `audit_event_redaction_redaction_id_seq`.
   - Attempts to update immutable metadata (`reason`, `requested_by`, `field_path`, `event_id`, etc.) fail with SQLState `42501 permission denied`.
   - Lifecycle trigger `trg_audit_event_redaction_lifecycle` permanently seals completed records (`55000: record is sealed and immutable once COMPLETED`), validates state transitions (`PENDING -> KEY_DESTROYED -> COMPLETED`), and mandates a positive `meta_audit_sequence_no`.
   - Delete trigger `trg_audit_event_redaction_no_delete` prohibits `DELETE` and `TRUNCATE` operations (`55000`).

### Export bundles with independent verification (Scenario B)

The service provides `GET /audit/exports` (implemented by `AuditExportController` and `AuditExportService`) to generate self-contained, versioned, independently verifiable audit bundles:

1. **Filtering and Mutual Exclusivity**:
   - Requires either `actorId` or `resourceId`. Supplying both or neither returns sanitized HTTP 400 `ErrorResponse`.
   - Blank values are actively rejected with HTTP 400.
   - `includeArchived` defaults to `true`, ensuring complete regulatory history is captured. Callers specifying `includeArchived=false` demote soft-archived records to witness nodes.
   - Requires authentication with role `AUDITOR` (HTTP 401 unauthenticated, HTTP 403 `AUDIT_WRITER`).

2. **Snapshot Consistency & Bounded Limits**:
   - Runs in a point-in-time database snapshot transaction under `@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)`.
   - Observes the singleton `audit_chain_head` row at transaction start to capture `(snapshotHeadSeq, snapshotHeadHash)`.
   - Enforces configurable upper bounds via `AuditExportProperties`:
     - `maxMatchedEvents` (default: 1,000): prevents memory exhaustion if a filter matches an unbounded volume of events. Exceeding the limit halts export immediately with a sanitized HTTP 413 `Payload Too Large` response.
     - `maxTotalRecords` (default: 10,000): bounds the total genesis-to-head witness chain length. Exceeding the limit halts export with HTTP 413.
   - Queries stream records strictly up to `sequence_no <= snapshotHeadSeq` ordered by `sequence_no ASC`. Because PostgreSQL holds a repeatable read snapshot across the queries, concurrent appends advancing the chain head or redacting records during export generation never produce dangling witness links, phantom events, or inconsistent redaction projections.
   - Deterministic JCS canonicalization (RFC 8785) ensures byte-for-byte reproducible content hashes.

3. **Sparse-Chain Witness Mechanics**:
   - Because filtering produces non-contiguous sequence numbers, the export bundle includes:
     - `events`: Full canonical records (with complete JSON payload) for all events matching the filter.
     - `witnesses`: Compact, privacy-preserving witness nodes $(\text{sequenceNo}, \text{previousHash}, \text{contentHash}, \text{recordHash})$ for non-matching records, connecting genesis ($0^{64}$) through to `chainHead`.
   - Discloses zero sensitive plaintext payloads, actor IDs, or resource IDs for intermediate events, while providing the exact hashes needed to recalculate the unbroken chain.

4. **Cross-Milestone Synthesis (Archival & Redaction)**:
   - **Soft Archival (Milestone 9)**: Returns active and soft-archived events by default (`includeArchived=true`), with `archivedAt` populated from `audit_event_archive`. Physical rows in `audit_event` are untouched, ensuring 100% hash verification pass.
   - **Structured Redaction (Milestone 10)**:
     - For crypto-shredded records (`CRYPTO_SHREDDED`), the stored ciphertext envelope is preserved in `payload`, allowing exact recalculation of `contentHash` while key destruction guarantees mathematical confidentiality. The accompanying `PAYLOAD_REDACTED` meta-event is returned as verifiable evidence. Both Java and Python verifiers report `status = INTACT`.
     - For legacy plaintext records (`MASKED`), projection masking (`"[REDACTED]"`) is applied to prevent leaking sensitive plaintext. Because the original plaintext is omitted from the export, recomputing the content hash over the masked JSON cannot match the stored ingestion hash commitment. The verifier verifies previous-hash linkage and record-hash commitments against stored hashes, but reports `status = PARTIALLY_VERIFIED_REDACTED`, explicitly distinguishing verified chain linkage from unverifiable masked payload content.

5. **Independent Verification Algorithm & Tooling**:
   - Standalone verifiers (`StandaloneExportVerifier` in Java, and `scripts/verify_export.py` in Python 3 standard library):
     1. Verifies sequence contiguity from sequence 1 to `chainHead.sequenceNo`.
     2. Verifies genesis hash linkage at sequence 1 ($0^{64}$).
     3. For unredacted and crypto-shredded events, recalculates RFC 8785 canonical content hash and asserts equality with stored `contentHash`.
     4. For legacy masked events, skips payload hash recomputation, verifies chain commitments, and increments `maskedEventsCount`.
     5. Recalculates domain-separated SHA-256 record hash for all records (events + witnesses) and verifies previous-hash linkage across every step.
     6. Verifies tail alignment against `chainHead.recordHash`.
     7. Asserts filter conformance for every exported event.
     8. Returns `INTACT` if all records match and zero masked events exist; returns `PARTIALLY_VERIFIED_REDACTED` if hash chain linkage is intact but legacy masked events are present; returns `CORRUPTED` on any link, hash, sequence, or filter failure.

6. **Security and Trust Boundaries**:
   - **Relative Trust Anchor**: The bundle's `chainHead` is an internal point-in-time database commitment. Detecting complete database history rewriting by a superuser requires an independently notarized external anchor.
   - **Inclusion vs. Completeness**: The bundle mathematically proves authenticity, tamper-evidence, and chain inclusion of all exported records. It cannot prove non-omission of matching records without disclosing intermediate third-party payloads or employing zero-knowledge set-membership proofs.

### Compliance reporting and regulator auditing (Scenario C / Milestone 12)

The service provides dedicated compliance reporting and export capabilities for external regulatory examiners (`ROLE_REGULATOR`):

1. **Banking Data Plane vs. Audit Plane Separation**:
   - The Audit Log Service does not hold live account balances or trading positions. It operates as the authoritative, tamper-evident *Audit Plane*.
   - Upstream banking systems (e.g. branch teller apps, CRM, advisor portals, API gateways) emit standardized client account access events via `POST /audit/events` with `resourceType = 'ACCOUNT'` and `resourceId = accountId` (actions: `ACCOUNT_VIEWED`, `ACCOUNT_SEARCHED`, `STATEMENT_DOWNLOADED`, `ACCOUNT_EXPORTED`, `ACCOUNT_MODIFIED`, `ACCOUNT_ACCESS_DENIED`).

2. **Regulator Export Isolation (Server-Side Enforcement)**:
   - `ROLE_REGULATOR` is strictly denied access to general `GET /audit/exports` (HTTP 403 Forbidden).
   - Regulatory exports use `GET /audit/compliance/account-access/export?accountId={accountId}`. The server requires non-blank `accountId` and forces `resourceType = 'ACCOUNT'`, ensuring examiners cannot export non-account resources or personal employee logs.
   - Non-matching records (including supervisory events) are demoted to compact hash witnesses. The resulting bundle adheres to `ExportBundleDto` specification (`bundleVersion: "1.0"`) and is 100% verifiable independently using `StandaloneExportVerifier` (Java) and `scripts/verify_export.py` (Python).

3. **Fail-Closed Supervisory Meta-Auditing**:
   - Every examination query (`GET /audit/compliance/account-access`) commits a `REGULATORY_AUDIT_ACCESSED` event to the ledger; each export commits a `REGULATORY_EXPORT_ACCESSED` event.
   - Supervisory events record examiner identity, requested account ID, query parameters, and correlation ID without leaking sensitive business payloads.
   - **Fail-Closed Execution Policy**: The supervisory append transaction executes first. If the append fails (e.g. database lock contention or disk failure), execution terminates immediately with a sanitized HTTP 503/500 error; zero client account data is ever read or disclosed.

4. **Supervisory Recursion & Query Isolation**:
   - Supervisory events are assigned `resourceType = 'COMPLIANCE_AUDIT'`.
   - Compliance queries strictly filter on `resourceType = 'ACCOUNT'`. Supervisory events never match the query predicate, preventing query feedback loops, pagination drift, or pollution of the client account's business access trail.
   - Global chain verification (`GET /audit/verify`) walks 100% of rows from genesis to head regardless of resource type, guaranteeing unbroken hash-chain integrity.

5. **Pagination Consistency & Multi-Request Stateless Reality**:
   - Paginated queries operate under single-request `READ COMMITTED` transactions ordered monotonically by `sequence_no ASC`.
   - New incoming events receive higher sequence numbers at the tail and never shift row offsets of previously retrieved pages.
   - Frozen point-in-time snapshot consistency is provided by the compliance export endpoint under `@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)`.

6. **Least Privilege & Role-Based Authorization**:
   - `ROLE_REGULATOR` is restricted to `/audit/compliance/account-access` and `/audit/compliance/account-access/export`.
   - General internal audit queries (`/audit/events`), unrestricted exports (`/audit/exports`), chain verification (`/audit/verify`), and all mutation endpoints (`/audit/events` POST, `/audit/archive/**`, `/audit/events/*/redact`) return HTTP 403 Forbidden.
   - Internal `ROLE_AUDITOR` retains access to all read, query, export, and verification endpoints. `ROLE_AUDIT_WRITER` is restricted to write, archive, and redact.

7. **Documented Production Scope Boundaries**:
   - *Subpoena / Matter Tracking*: In enterprise production, regulatory queries mandate an external subpoena or examination reference (e.g. `matterId = "SEC-EXAM-2026-04"`) in request headers.
   - *Upstream Data Plane Ingestion*: Live banking gateways emit access events via distributed streaming pipelines (e.g. Apache Kafka) with dead-letter replay.
   - *mTLS & PKI Federation*: Regulators authenticate via hardware-backed client certificate mTLS rather than HTTP Basic credentials.

## Threat model and limitations

### 1. Ledger Integrity & Trust Boundary Analysis

The cryptographic hash chain implemented by the Audit Log Service establishes strong mathematical guarantees:
- **Tamper Evidence**: Any modification to an event payload, stored content hash, genesis hash, intermediate link, sequence ordering, or chain head pointer produces an immediate mismatch detectable by `GET /audit/verify` and export bundle verifiers.
- **Append-Only Enforcement**: PostgreSQL triggers (`trg_audit_event_no_update_delete`) and restrictive role grants (`audit_app` granted `SELECT, INSERT` only) prevent modification or deletion through standard application workflows.

#### The Privileged DBA Superuser Threat Model
- **What Internal Chains Prove**: The internal chain proves that all committed records from genesis to `audit_chain_head` are cryptographically linked and unmodified relative to the stored chain-head pointer.
- **What Internal Chains Cannot Prove**: A privileged database administrator (DBA) with PostgreSQL superuser permissions (`postgres`) has complete control over the storage engine. A superuser can:
  1. Temporarily disable triggers (`ALTER TABLE audit_event DISABLE TRIGGER ALL;`).
  2. Modify a historical row's payload or delete a target sequence.
  3. Sequentially recompute all subsequent `content_hash`, `previous_hash`, and `record_hash` values forward to the tail.
  4. Update `audit_chain_head.last_record_hash` to match the newly rewritten tail.
  5. Re-enable triggers (`ALTER TABLE audit_event ENABLE TRIGGER ALL;`).
  Because `GET /audit/verify` relies on the database's own `audit_chain_head` as its local trust anchor, it would evaluate the rewritten chain as `status: INTACT`.

#### Production Mitigation: External Trust Anchors
To defend against superuser history rewriting, enterprise production deployments must publish signed checkpoints beyond the administrative perimeter of the database:
1. **Cryptographic Transparency Logs (RFC 6962)**: Structure ledger checkpoints into an append-only Merkle Tree where Signed Tree Heads (STHs) are published to independent auditors, providing logarithmic inclusion and consistency proofs.
2. **External Timestamping Authority (RFC 3161 TSA)**: Periodically submit the latest `(sequence_no, record_hash)` to an external RFC 3161 compliant timestamping authority to obtain cryptographically verifiable, third-party signed timestamp tokens.
3. **Write-Once-Read-Many (WORM) Storage**: Mirror chain-head checkpoints and export bundles to cloud storage configured with strict compliance-mode object locking (e.g., AWS S3 Object Lock in Compliance Mode), where retention periods cannot be shortened or deleted even by the AWS account root user.
4. **Public Distributed Ledger Anchoring**: Periodically anchor the state root hash to a public or consortium blockchain, creating an immutable, globally observable timestamped witness.

### 2. Key Management & Crypto-Shredding Lifecycle

- **Prototype Scope**: The prototype uses `InMemoryKeyManager` to store Data Encryption Keys (DEKs) in JVM memory for automated test validation.
- **Production Scope**: Enterprise deployments must integrate `KeyManager` with an external Hardware Security Module (HSM) or managed Key Management Service (e.g., AWS KMS, HashiCorp Vault, Azure Key Vault):
  - **Envelope Encryption**: Master Key Encryption Keys (KEKs) remain securely inside the HSM. DEKs are generated per-record, encrypted under the KEK, and stored alongside the ciphertext envelope.
  - **Irrevocable Destruction**: True crypto-shredding requires calling the KMS key destruction API (e.g., `ScheduleKeyDeletion` or `DestroyKey`), rendering stored ciphertext permanently indecipherable across all database backups, read replicas, and write-ahead logs (WAL).
  - **Audit Trail**: KMS access and destruction operations generate independent CloudTrail/audit logs outside the database DBA's jurisdiction.

### 3. Rate Limiting & Distributed Topologies

- **Node-Local Token Bucket**: The implemented `TokenBucketRateLimiter` provides thread-safe, nano-second token replenishment and bounded capacity per JVM node.
- **Distributed Gateway Tier**: In a multi-replica Kubernetes deployment behind a load balancer, node-local token buckets do not coordinate token consumption across pods. Production systems must:
  - Enforce global edge rate limiting at the ingress/API gateway layer (e.g., Envoy rate-limit service, Kong) before traffic reaches application pods.
  - Or back the application rate-limiting filters with a shared, low-latency distributed store (e.g., Redis cluster using Redis cell or Lua token-bucket scripts).
- **Reverse Proxy IP Trust**: In production, `PreAuthIpRateLimitingFilter` extracts client IPs via `RemoteIpFilter`. The filter must be configured with an explicit list of trusted internal proxy CIDRs (`internalProxies`) to prevent malicious callers from spoofing their identity through untrusted `X-Forwarded-For` request headers.

### 4. TLS Termination & Network Perimeter

- **Internal Container Boundary**: The service container listens on HTTP internally, architected for deployment within a private VPC or Kubernetes service mesh (e.g., Istio, Linkerd) where sidecars manage pod-to-pod mutual TLS (mTLS) transparently.
- **Edge Termination**: External TLS 1.3 termination, cipher suite negotiation, and client certificate validation occur at the edge ingress controller or reverse proxy (e.g., AWS Application Load Balancer, Cloudflare), isolating network transport encryption from core application business logic.
