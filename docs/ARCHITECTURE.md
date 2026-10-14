# Architecture

## Components

| Component | Responsibility |
| --- | --- |
| REST controllers | Validate API requests, map responses, and delegate to application services. |
| Application services | Own append, search, verification, archival, redaction projection, and export workflows. |
| Hash service | Canonicalizes event content and computes SHA-256 hashes. |
| JPA repositories | Persist events and query filters; use a native lock query for the chain head. |
| PostgreSQL | Holds immutable audit events, the chain head, and separate archival metadata. |
| Spring Security | Provides stateless HTTP Basic authentication and endpoint authorization. |

## API contracts

| Endpoint | Contract | Authorization |
| --- | --- | --- |
| `POST /audit/events` | Accepts `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, and optional `sourceTimestamp`; returns `201` with event ID, sequence, server time, and hashes. | `AUDIT_WRITER` |
| `GET /audit/events` | Optional `actorId`, `resourceType`, `resourceId`, `eventType`, `from`, `to`, `page`, `size`, and later `includeArchived`; returns a stable sequence-ordered page. | `AUDITOR` |
| `GET /audit/verify` | Verifies the full global chain; returns intact status or first sequence and violation type. | `AUDITOR` |
| `GET /audit/exports` | Scenario B endpoint. Requires exactly one of `actorId` or `resourceId`; returns a verifiable bundle. | `AUDITOR` |

No `PUT`, `PATCH`, or `DELETE` audit-event endpoint will exist. Unauthenticated requests receive `401`; authenticated callers without the required role receive `403`.

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

Scenario B metadata keyed by `event_id`, containing archival time, policy reference, and archival location. It is not part of the immutable event content hash. The original event remains present for verification.

## Hash chain

### Canonical event content

`content_hash` is `SHA-256` of UTF-8 RFC 8785 JSON Canonicalization Scheme content with this exact shape:

```json
{
  "canonicalizationVersion": "JCS-1",
  "eventId": "uuid",
  "eventType": "USER_LOGIN",
  "actorId": "actor-123",
  "resourceType": "ACCOUNT",
  "resourceId": "account-456",
  "payload": { "canonical": "json" },
  "sourceTimestamp": "2026-10-14T15:00:00.123Z",
  "recordedAt": "2026-10-14T15:00:01.456Z"
}
```

Optional `sourceTimestamp` is represented as JSON `null` when absent. Timestamps use UTC and millisecond precision. Objects sort keys, arrays retain order, strings use UTF-8, and numbers follow JCS normalization. The service hashes parsed payload values, never raw request text.

The first event uses the 64-character lowercase-zero genesis hash. Each `record_hash` is SHA-256 over length-prefixed UTF-8 components in this order: `AUDIT_RECORD_V1`, `sequence_no`, `previous_hash`, and `content_hash`. Length prefixes remove field-boundary ambiguity.

### Append transaction and concurrency

The append service runs one transaction:

1. Lock the singleton chain-head row with `SELECT ... FOR UPDATE`.
2. Derive the next sequence and previous hash.
3. Canonicalize and hash the event, then insert it.
4. Update the chain-head row with the new sequence and record hash.
5. Commit both writes together.

The head-row lock serializes writers. A failed insert, hash computation, or head update rolls back the whole transaction. This limits write throughput but is a clear and correct prototype trade-off.

Database triggers provide defense in depth for the same ordering. The insert trigger locks the chain head and accepts only the next sequence with the current head hash as `previous_hash`. The head-update trigger then requires that inserted event to have the new head sequence and hash. A deferred constraint trigger rejects a transaction that inserts an event without advancing the head to it. The service still takes the lock explicitly before calculating hashes; application-level concurrency has not yet been integration-tested.

The chain-head linkage protection is delivered as a forward-only Flyway `V2` migration. Fresh databases apply `V1` followed by `V2`; databases that already recorded `V1` retain their migration history and receive `V2` on the next Flyway run.

### Verification behavior

Verification reads rows by `sequence_no` and stops at the first error. It checks genesis use, contiguous sequence numbers, recomputed content hashes, recomputed record hashes, and previous-link equality. It finally compares the last scanned row to `audit_chain_head`.

Violation types include `GENESIS_MISMATCH`, `SEQUENCE_GAP`, `CONTENT_HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `RECORD_HASH_MISMATCH`, and `CHAIN_HEAD_MISMATCH`. This detects altered payloads, altered stored hashes, broken links, reordered rows, deleted middle rows, and deleted final rows when the local chain head remains unchanged.

## Append-only controls

The normal application database role receives only the minimum `SELECT` and `INSERT` rights for audit events. Migration and administrative identities are separate. PostgreSQL triggers reject `UPDATE`, `DELETE`, and `TRUNCATE` against `audit_event`; normal application APIs expose no mutation routes.

For local development, Docker Compose starts PostgreSQL as `audit_migrator` and bootstraps the limited `audit_app` role. Flyway runs with the migrator identity; the application uses `audit_app`. PostgreSQL is bound only to the loopback interface for host access. Operational environments must provision equivalent roles before migration. These controls prevent accidental application mutations, but schema owners and superusers can change permissions, disable triggers, or rewrite data.

The required tampering demonstration uses a separately authorized administrative connection in a documented test procedure. It temporarily bypasses the protection or uses a maintenance-only path to alter a row, then calls the ordinary verification API. The application role never receives update or delete rights.

## Security

The prototype uses stateless HTTP Basic authentication over TLS outside local development. Passwords use BCrypt hashes and credentials come from environment-backed configuration rather than source control. CSRF is disabled because this API uses stateless `Authorization` headers and does not use browser-managed sessions.

| Role | Allowed operations |
| --- | --- |
| `AUDIT_WRITER` | Create audit events. |
| `AUDITOR` | Query events, verify the chain, and export records. |

Production controls would add centralized identity, short-lived credentials, TLS termination, secret management, network restrictions, auditing of privileged database access, and separate operational roles.

## Retention, redaction, and export

Soft archival records metadata without mutating the original chain row. Verification always scans archived events. Redaction uses encrypted payload envelopes before hashing; the stored ciphertext and envelope metadata stay immutable, while removing the decryption key produces a redacted response projection.

Key destruction does not remove ciphertext, cannot recall previously disclosed plaintext, and depends on robust key management. It is an explicit prototype limitation.

An export includes selected canonical events, their hashes, a hash-only witness sequence between the first and last selected record, and the observed chain-head checkpoint. Recipients can recompute selected hashes and link continuity using the bundle.

## Threat model and limitations

The design detects accidental changes and unauthorized edits that do not also rewrite every affected hash and the chain head. A database administrator with sufficient privileges could rewrite the entire local chain and recompute hashes. A production claim against that threat requires a periodically signed checkpoint stored beyond PostgreSQL control, such as an independently controlled immutable store or key-management service.
