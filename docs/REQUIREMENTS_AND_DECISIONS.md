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

### Acceptance criteria

- A valid event is appended with a monotonic sequence, its hashes, and the prior record hash.
- All documented filter combinations return the expected stable pages.
- Direct changes to payloads, hashes, links, or row presence cause `/audit/verify` to report the first detectable violation.

## Scenario B: Retention, Redaction, and Export

### Requirements

- Records older than a configurable retention window must be archivable or soft-deletable without false chain failures.
- Sensitive payload fields must be redactable without breaking tamper evidence.
- Export all records for an `actorId` or `resourceId` as a self-contained verifiable bundle.
- Document the redaction design, alternatives, limitations, and trade-offs.

### Assumptions

- The prototype can retain immutable event evidence while presenting archived and redacted read projections.

### Recommendations

- Retention initially means soft archival: immutable chain records remain available to verification while normal queries may omit archived records.
- Archive state belongs in metadata separate from the immutable audit event, so archiving never changes a hashed row.
- Sensitive fields are represented as encrypted payload envelopes before the event is hashed. Redaction disables or destroys the referenced decryption key and returns a redacted projection.
- The initial export includes selected full records and hash-only witness records needed to establish continuity between the first and last selected sequence. It also includes the observed chain-head checkpoint.

### Acceptance criteria

- Archiving does not alter verification of the complete chain.
- A redacted response never exposes protected plaintext, while the original ciphertext envelope remains verifiable.
- An exported bundle verifies selected event content and chain continuity using only its contents, subject to the trusted-anchor limitation recorded below.

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
