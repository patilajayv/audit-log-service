# Charles Schwab FDE Audit Log Service — Live Interview Demo Guide

**Target System:** `/Users/ajaypatil/Downloads/FDE/audit-log-service`
**Runtime:** Java 17, Spring Boot 3.4.5, PostgreSQL 16 (Docker Compose)
**Verification Baseline:** 272 Automated Tests Passing Across 23 Test Classes
**Standard Port:** `http://localhost:8080` (or `http://localhost:8080` with DB on `5433` if port 5432 is occupied)

---

## 1. Executive Demo Sequence (10–15 Minute Flow)

| Time | Phase | Target Concept | Key Command / Action |
|---|---|---|---|
| **0:00 – 1:30** | **Architecture Brief** | Problem statement, 3 scenarios, threat model | Point to architecture diagram in `docs/ARCHITECTURE.md` |
| **1:30 – 3:30** | **Step 1: Event Ingestion** | Append-only, RFC 8785 canonical hash, chain head lock | `POST /audit/events` (Writer role) |
| **3:30 – 5:00** | **Step 2: Filtered Queries** | Multi-criteria filtering, stable pagination | `GET /audit/events` (Auditor role) |
| **5:00 – 7:00** | **Step 3: Verification & Tampering** | Full-chain recomputation, direct database tamper detection | `GET /audit/verify` $\rightarrow$ DB update $\rightarrow$ `GET /audit/verify` |
| **7:00 – 8:30** | **Step 4: Retention & Archival** | Soft archival, separate metadata, zero false positives | `POST /audit/archive/{id}` $\rightarrow$ query with `includeArchived` |
| **8:30 – 10:30** | **Step 5: Structured Redaction** | AES-256-GCM envelope crypto-shredding, projection masking | `POST /audit/events/{id}/redact` $\rightarrow$ query masked payload |
| **10:30 – 12:30** | **Step 6: Bulk Export & Python Verifier** | Verifiable export bundle, witness chains, zero-dependency verifier | `GET /audit/exports` $\rightarrow$ `python3 scripts/verify_export.py` |
| **12:30 – 14:00** | **Step 7: Regulator Compliance** | Scenario C: Server-side account scoping, supervisory meta-audit | `GET /audit/compliance/account-access` (Regulator role) |
| **14:00 – 15:00** | **Step 8: Least Privilege & Defense** | Strict RBAC, default deny, sanitized 401/403 responses | 401 unauthenticated, 403 role-denial tests |

---

## 2. Pre-Demo Environment & Service Checklist

Before launching the demo, ensure the environment and database are ready:

### 2.1 Terminal Shell Setup
In your demonstration terminal window, export credential variables corresponding to the active Spring Boot profile:

```bash
# Local development profile credentials (matching application-local.yaml)
export BASE_URL="http://localhost:8080"
export WRITER_USER="local_writer"
export WRITER_PASS="local-writer-secret-password"
export AUDITOR_USER="local_auditor"
export AUDITOR_PASS="local-auditor-secret-password"
export REGULATOR_USER="local_regulator"
export REGULATOR_PASS="local-regulator-secret-password"
```

### 2.2 Verify Database Container
Start the PostgreSQL 16 container:
```bash
cd /Users/ajaypatil/Downloads/FDE/audit-log-service
docker compose up -d
```

### 2.3 Start Application
If port 5432 is occupied by a host database (as on macOS with native PostgreSQL), use the isolated Compose mapping on port 5433:

```bash
AUDIT_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
AUDIT_MIGRATOR_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
mvn spring-boot:run -Dspring-boot.run.profiles=local
```
Wait for the log message: `Started AuditLogServiceApplication in ... seconds`.

---

## 3. Step-by-Step Live Demo Script

---

### Step 1: Audit Event Ingestion & Append-Only Hash-Chain Generation

#### Command
```bash
curl -i -X POST "$BASE_URL/audit/events" \
  -u "$WRITER_USER:$WRITER_PASS" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: demo-ingest-001" \
  -d '{
    "eventType": "ACCOUNT_VIEWED",
    "actorId": "advisor-jsmith",
    "resourceType": "ACCOUNT",
    "resourceId": "ACCT-987654",
    "payload": {
      "channel": "WEALTH_DESK",
      "ipAddress": "10.240.12.8",
      "viewType": "PORTFOLIO_BALANCES"
    },
    "sourceTimestamp": "2026-10-15T10:30:00Z"
  }'
```

#### Authorization & Roles
- **Role Required:** `ROLE_AUDIT_WRITER` (`local_writer`)
- **Expected Status:** `HTTP/1.1 201 Created`

#### Key Response Fields to Highlight
```json
{
  "eventId": "123e4567-e89b-12d3-a456-426614174000",
  "sequenceNo": 1,
  "eventType": "ACCOUNT_VIEWED",
  "actorId": "advisor-jsmith",
  "resourceType": "ACCOUNT",
  "resourceId": "ACCT-987654",
  "recordedAt": "2026-10-15T12:15:30.123Z",
  "canonicalizationVersion": "JCS-1",
  "contentHash": "5a4b...",
  "previousHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "recordHash": "8f3e..."
}
```
*(Save the returned `eventId` for Steps 4 and 5: `export EVENT_ID="<returned-event-id>"`)*

#### What This Demonstrates
1. Ingestion of structured audit records with server-assigned monotonic sequence numbers.
2. Canonical hash calculation using RFC 8785 JSON Canonicalization Scheme (JCS).
3. First event references the 64-character all-zero genesis previous hash; subsequent events link to the previous record's `recordHash`.
4. Concurrency protection via row-level `SELECT ... FOR UPDATE` locking on `audit_chain_head`.

#### Verbal Interview Talking Points
> *"Notice the hash chain commitments returned: `contentHash` is calculated using RFC 8785 (JCS) canonical JSON, meaning property ordering, scientific notation, and float representation are completely deterministic. `previousHash` for sequence 1 links to our 64-zero genesis constant. The `recordHash` uses length-prefixed domain separation over `AUDIT_RECORD_V1`, sequence, previous hash, and content hash, eliminating field-boundary ambiguity. In PostgreSQL, this transaction locks the singleton chain-head row, derives sequence $N+1$, writes the record, updates the head, and commits atomically."*

---

### Step 2: Querying Events with Filters & Stable Pagination

#### Command
```bash
curl -i -X GET "$BASE_URL/audit/events?resourceType=ACCOUNT&resourceId=ACCT-987654&page=0&size=10" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" \
  -H "X-Correlation-ID: demo-query-001"
```

#### Authorization & Roles
- **Role Required:** `ROLE_AUDITOR` (`local_auditor`)
- **Expected Status:** `HTTP/1.1 200 OK`

#### Key Response Fields to Highlight
```json
{
  "events": [
    {
      "sequenceNo": 1,
      "eventId": "123e4567-...",
      "eventType": "ACCOUNT_VIEWED",
      "actorId": "advisor-jsmith",
      "resourceType": "ACCOUNT",
      "resourceId": "ACCT-987654",
      "payload": { ... },
      "recordedAt": "2026-10-15T12:15:30.123Z",
      "contentHash": "5a4b...",
      "previousHash": "0000...",
      "recordHash": "8f3e...",
      "archivedAt": null
    }
  ],
  "page": 0,
  "size": 10,
  "totalElements": 1,
  "totalPages": 1,
  "first": true,
  "last": true
}
```

#### What This Demonstrates
1. Secure, parameterized query execution filtering on composite index `(resource_type, resource_id)`.
2. Deterministic sequence ordering (`ORDER BY sequence_no ASC`).
3. Read-only transaction enforcement (`@Transactional(readOnly = true)`).
4. Pagination stability: newly appended events appear at the tail and never shift offsets of earlier pages.

#### Verbal Interview Talking Points
> *"We expose read-only querying to users with the `AUDITOR` role. Queries are executed with 100% parameterized SQL to prevent injection. Pagination is ordered strictly by `sequence_no ASC`. Because this is an append-only ledger, new incoming events are written to the tail of the chain, preventing page drift. Notice also that the service runs under `@Transactional(readOnly = true)`, and operational logs record only correlation IDs, completely suppressing client account numbers and payloads."*

---

### Step 3: Full-Chain Integrity Verification & Tamper Detection

#### Part A: Verify Intact Chain
```bash
curl -i -X GET "$BASE_URL/audit/verify" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" \
  -H "X-Correlation-ID: demo-verify-001"
```
**Expected Status:** `HTTP/1.1 200 OK`
```json
{
  "status": "INTACT",
  "recordsVerified": 2,
  "headSequenceNo": 2,
  "headRecordHash": "...",
  "lastVerifiedSequenceNo": 2,
  "lastVerifiedRecordHash": "...",
  "violation": null
}
```

#### Part B: Tamper Demonstration (Direct Database Alteration)
Simulate an attacker or administrator modifying a record directly in PostgreSQL:
```bash
# Connect to PostgreSQL container and simulate unauthorized payload alteration
docker exec -i audit-log-service-postgres-1 psql -U audit_migrator -d audit_log << 'EOF'
-- Temporarily disable append-only trigger to simulate an admin tamper
ALTER TABLE audit_event DISABLE TRIGGER audit_event_reject_update_delete;

-- Alter payload in row sequence 2
UPDATE audit_event
SET payload = '{"channel":"WEALTH_DESK","viewType":"TAMPERED_DATA"}'::jsonb
WHERE sequence_no = 2;

-- Re-enable trigger
ALTER TABLE audit_event ENABLE TRIGGER audit_event_reject_update_delete;
EOF
```

#### Part C: Re-run Verification (Tamper Detected)
```bash
curl -i -X GET "$BASE_URL/audit/verify" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" \
  -H "X-Correlation-ID: demo-verify-tampered"
```
**Expected Status:** `HTTP/1.1 200 OK`
```json
{
  "status": "CORRUPTED",
  "recordsVerified": 1,
  "headSequenceNo": 2,
  "headRecordHash": "...",
  "lastVerifiedSequenceNo": 1,
  "lastVerifiedRecordHash": "...",
  "violation": {
    "type": "CONTENT_HASH_MISMATCH",
    "sequenceNo": 2,
    "eventId": "...",
    "expected": "...",
    "actual": "...",
    "message": "Content hash mismatch at sequence 2: stored content_hash does not match canonical payload content"
  }
}
```

#### Part D: Restore Clean State (Post-Tamper Clean-Up)
```bash
# Restore original payload for subsequent demo steps
docker exec -i audit-log-service-postgres-1 psql -U audit_migrator -d audit_log << 'EOF'
ALTER TABLE audit_event DISABLE TRIGGER audit_event_reject_update_delete;
UPDATE audit_event
SET payload = '{"channel":"WEALTH_DESK","ipAddress":"10.240.12.8","viewType":"PORTFOLIO_BALANCES"}'::jsonb
WHERE sequence_no = 2;
ALTER TABLE audit_event ENABLE TRIGGER audit_event_reject_update_delete;
EOF
```

#### What This Demonstrates
1. Full-chain streaming cursor recalculation (`fetchSize = 500`).
2. Immediate violation detection (`CONTENT_HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `SEQUENCE_GAP`, `CHAIN_HEAD_MISMATCH`).
3. Defense in depth: normal database users cannot execute `UPDATE` or `DELETE` due to PostgreSQL triggers; even if a superuser bypasses triggers, the cryptographic chain instantly catches the alteration.

#### Verbal Interview Talking Points
> *"Here we demonstrate our tamper-evidence guarantee. In Part A, `/audit/verify` streams records and recomputes canonical hashes, confirming `INTACT`. In Part B, we demonstrate defense-in-depth: our schema enforces an append-only trigger blocking updates. Even if an administrative attacker disables the trigger and modifies the JSON payload directly in PostgreSQL, calling `/audit/verify` recomputes the RFC 8785 hash, immediately detects `CONTENT_HASH_MISMATCH` at sequence 2, and stops the scan with full diagnostic details."*

---

### Step 4: Retention, Archival, & Archived-Event Filtering

#### Command: Archive Event
```bash
curl -i -X POST "$BASE_URL/audit/archive/$EVENT_ID" \
  -u "$WRITER_USER:$WRITER_PASS" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: demo-archive-001" \
  -d '{
    "policyRef": "RETENTION_POLICY_7_YEAR_RULE"
  }'
```

#### Authorization & Roles
- **Role Required:** `ROLE_AUDIT_WRITER` (`local_writer`)
- **Expected Status:** `HTTP/1.1 200 OK`

#### Key Response Fields to Highlight
```json
{
  "eventId": "...",
  "archived": true,
  "archivedAt": "2026-10-15T12:37:39.867Z",
  "policyRef": "RETENTION_POLICY_7_YEAR_RULE"
}
```

#### Command: Verify Default Query Excludes Archived Events
```bash
curl -s -X GET "$BASE_URL/audit/events?resourceType=ACCOUNT&resourceId=ACCT-987654" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" | jq '.totalElements'
# Output: 0
```

#### Command: Verify Query Includes Archived Events when Explicitly Requested
```bash
curl -s -X GET "$BASE_URL/audit/events?resourceType=ACCOUNT&resourceId=ACCT-987654&includeArchived=true" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" | jq '.events[0] | {sequenceNo, eventId, archivedAt}'
# Output shows event with populated "archivedAt" timestamp
```

#### What This Demonstrates
1. Soft archival implemented via separate metadata table `audit_event_archive` (Flyway V3).
2. Physical rows in `audit_event` are **never updated or deleted**.
3. `GET /audit/verify` continues to return `status: INTACT` with zero false-positive chain breaks.
4. Default query exclusion protects active operational views while preserving regulatory retrieval.

#### Verbal Interview Talking Points
> *"A critical challenge in Scenario B is handling retention without breaking cryptographic hash chains. If we deleted or altered the record, every subsequent hash pointer through to the chain head would be invalidated. Instead, we implement soft archival: `audit_event` remains immutable, while archival state is stored in `audit_event_archive`. Calling `/audit/verify` still traverses the unbroken chain and returns `INTACT`. Queries exclude archived events by default, but compliance examiners can specify `includeArchived=true` to retrieve full regulatory history."*

---

### Step 5: Structured Payload Redaction & Read-Time Masking

#### Command: Ingest Event with Sensitive Account Number
```bash
INGEST_RES=$(curl -s -X POST "$BASE_URL/audit/events" \
  -u "$WRITER_USER:$WRITER_PASS" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "WIRE_TRANSFERRED",
    "actorId": "teller-44",
    "resourceType": "ACCOUNT",
    "resourceId": "ACCT-987654",
    "payload": {
      "accountNumber": "9876543210",
      "routingNumber": "121000358",
      "amount": "25000.00"
    }
  }')
export REDACT_EVENT_ID=$(echo $INGEST_RES | jq -r '.eventId')
echo "Created event: $REDACT_EVENT_ID"
```

#### Command: Redact Sensitive Field
```bash
curl -i -X POST "$BASE_URL/audit/events/$REDACT_EVENT_ID/redact" \
  -u "$WRITER_USER:$WRITER_PASS" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: demo-redact-001" \
  -d '{
    "fieldPath": "accountNumber",
    "reason": "CCPA_RIGHT_TO_ERASURE_REQUEST_8821",
    "requestedBy": "dpo-compliance@schwab.com"
  }'
```

#### Authorization & Roles
- **Role Required:** `ROLE_AUDIT_WRITER` (`local_writer`)
- **Expected Status:** `HTTP/1.1 200 OK`

#### Key Response Fields to Highlight
```json
{
  "eventId": "...",
  "fieldPath": "accountNumber",
  "status": "COMPLETED",
  "redactionType": "MASKED",
  "redactedAt": "2026-10-15T12:41:22.288Z",
  "metaAuditSequenceNo": 5
}
```

#### Command: Verify Read-Time Masking Projection
```bash
curl -s -X GET "$BASE_URL/audit/events?eventType=WIRE_TRANSFERRED" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" | jq '.events[] | select(.sequenceNo==4) | .payload'
```
**Output:**
```json
{
  "accountNumber": "[REDACTED]",
  "amount": "25000.00",
  "routingNumber": "121000358"
}
```

#### What This Demonstrates
1. Redaction of sensitive fields without modifying historical database hashes.
2. Read projection automatically replaces the targeted property with `"[REDACTED]"`.
3. An immutable `PAYLOAD_REDACTED` meta-audit event is appended to the ledger (linking `metaAuditSequenceNo`).
4. Database lifecycle triggers (`trg_audit_event_redaction_lifecycle`) seal completed redaction records permanently.

#### Verbal Interview Talking Points
> *"In Scenario B, data privacy laws like GDPR and CCPA require redacting sensitive PII, but modifying the stored JSON breaks the SHA-256 content hash. We solve this with dual architecture: for encrypted fields, our pluggable `KeyManager` permanently crypto-shreds the data encryption key; for legacy fields, we register metadata in `audit_event_redaction` and project `[REDACTED]` at read time. Furthermore, an immutable `PAYLOAD_REDACTED` event is appended to the chain. Pre-append reconciliation ensures that if an operation is retried, duplicate meta-events are never created."*

---

### Step 6: Audit Export Generation & Standalone Python Verification

#### Command: Generate Verifiable Export Bundle
```bash
curl -s -X GET "$BASE_URL/audit/exports?resourceId=ACCT-987654" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" \
  -H "X-Correlation-ID: demo-export-001" > export_bundle.json
```

#### Authorization & Roles
- **Role Required:** `ROLE_AUDITOR` (`local_auditor`)
- **Expected Status:** `HTTP/1.1 200 OK`

#### Command: Execute Standalone Zero-Dependency Python Verifier
```bash
python3 scripts/verify_export.py export_bundle.json
```

#### Expected Verifier Output
```text
EXPORT BUNDLE INDEPENDENT VERIFICATION RESULT
============================================================
Status:               PARTIALLY_VERIFIED_REDACTED
Total Records Linked: 5
Matched Events:       3
Masked Events:        1
Head Sequence No:     5
Head Record Hash:     211147d9598502b5e7c7bb85baadeff75abf5a9dabc86db2f67237a97d5b7613
============================================================
Hash chain linkage verified intact. Matched payloads with legacy redaction (MASKED) are unverifiable against stored content hashes because original plaintext was omitted.
```

#### What This Demonstrates
1. Bulk export operates under `@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)` snapshot consistency.
2. Non-matching events are converted into privacy-preserving witness nodes (disclosing zero third-party payloads).
3. The bundle is verified independently by a standalone Python 3 script using standard library modules only (`hashlib`, `json`, `struct`).
4. Milestone 11 hardening: masked payloads are honestly reported as `PARTIALLY_VERIFIED_REDACTED` rather than falsely claiming content-hash match.

#### Verbal Interview Talking Points
> *"In Scenario B, bulk exports must be self-contained and verifiable by an independent external third party without database access. Our service streams records under a repeatable-read snapshot transaction. Matching records contain the full canonical event; non-matching records are emitted as witness nodes containing only sequence numbers and hashes. The recipient can run `scripts/verify_export.py` using pure standard-library Python to prove sequence contiguity, genesis linkage, and cryptographic hash continuity from sequence 1 to the declared chain head."*

---

### Step 7: Regulator Account-Access Auditing & Supervisory Meta-Events (Scenario C)

#### Command: Regulatory Query
```bash
curl -i -X GET "$BASE_URL/audit/compliance/account-access?accountId=ACCT-987654" \
  -u "$REGULATOR_USER:$REGULATOR_PASS" \
  -H "X-Correlation-ID: sec-examination-8821"
```

#### Authorization & Roles
- **Role Required:** `ROLE_REGULATOR` (`local_regulator`) or `ROLE_AUDITOR`
- **Expected Status:** `HTTP/1.1 200 OK`

#### Key Response Fields to Highlight
1. Returns all client account access events with `resourceType = "ACCOUNT"`.
2. Soft-archived events are included by default (`includeArchived = true`) to satisfy full regulatory discovery.

#### Command: Verify Fail-Closed Supervisory Meta-Audit Event
Inspect the audit log using internal auditor credentials to confirm supervisory logging:
```bash
curl -s -X GET "$BASE_URL/audit/events?resourceType=COMPLIANCE_AUDIT&includeArchived=true" \
  -u "$AUDITOR_USER:$AUDITOR_PASS" | jq '.events[] | select(.eventType=="REGULATORY_AUDIT_ACCESSED")'
```

**Output:**
```json
{
  "sequenceNo": 6,
  "eventType": "REGULATORY_AUDIT_ACCESSED",
  "actorId": "local_regulator",
  "resourceType": "COMPLIANCE_AUDIT",
  "resourceId": "ACCT-987654",
  "payload": {
    "action": "QUERY_ACCOUNT_ACCESS",
    "examiner": "local_regulator",
    "accountId": "ACCT-987654",
    "correlationId": "sec-examination-8821"
  }
}
```

#### What This Demonstrates
1. Clarified ambiguous requirement: separation between audit plane and banking data plane.
2. Server-side forced account scoping preventing regulators from exporting arbitrary company resources.
3. Fail-closed supervisory meta-auditing: every examination query durably appends an immutable audit event *before* disclosing account data.
4. Supervisory recursion prevention: supervisory events use `resourceType = 'COMPLIANCE_AUDIT'`, isolating them completely from account query results and preventing infinite query loops or pagination drift.

#### Verbal Interview Talking Points
> *"Scenario C presented an intentionally ambiguous requirement: 'Regulators need to be able to audit access to client account data.' We normalized this requirement through disciplined engineering: first, the audit service is the audit plane, not the live banking ledger. Second, compliance queries mandate fail-closed supervisory meta-auditing: under FINRA and SEC oversight, 'auditing the auditor' is mandatory. We commit a `REGULATORY_AUDIT_ACCESSED` event to the chain in a dedicated transaction before returning account records. Third, to prevent supervisory events from polluting the account's query results or triggering pagination drift, we isolate them under `resourceType = 'COMPLIANCE_AUDIT'`."*

---

### Step 8: Authentication, Role-Based Authorization, & Negative Tests

#### Test 8A: Unauthenticated Request (Sanitized 401 Challenge)
```bash
curl -i -X GET "$BASE_URL/audit/events"
```
**Expected Status:** `HTTP/1.1 401 Unauthorized`
**Headers & Body:**
```text
WWW-Authenticate: Basic realm="AuditLogService"
Content-Type: application/json

{"status":401,"error":"Unauthorized","message":"Full authentication is required to access this resource"}
```

#### Test 8B: Least-Privilege Role Denial (Sanitized 403 Forbidden)
Demonstrate that a regulator cannot invoke unrestricted internal audit queries:
```bash
curl -i -X GET "$BASE_URL/audit/events" \
  -u "$REGULATOR_USER:$REGULATOR_PASS"
```
**Expected Status:** `HTTP/1.1 403 Forbidden`
**Body:**
```json
{"status":403,"error":"Forbidden","message":"Access is denied: insufficient role privileges"}
```

#### Test 8C: Default Deny on Unmapped Routes
```bash
curl -i -X GET "$BASE_URL/audit/nonexistent-endpoint" \
  -u "$WRITER_USER:$WRITER_PASS"
```
**Expected Status:** `HTTP/1.1 403 Forbidden` (Enforced via `.anyRequest().denyAll()`)

#### What This Demonstrates
1. Strict defense-in-depth security model with fail-fast filter enforcement.
2. Sanitized error messages suppressing internal SQL syntax, stack traces, and table structures.
3. Database immutability: rejected requests (401, 403) never insert records or advance sequence counters.

#### Verbal Interview Talking Points
> *"Our security architecture follows strict least-privilege separation. We define three distinct roles: `AUDIT_WRITER` can append and archive; `AUDITOR` can query and verify; `REGULATOR` is restricted strictly to compliance account endpoints. Any unauthorized access returns sanitized JSON errors without leaking stack traces or schema details. Unmapped routes are denied by default."*

---

## 4. Live Environment Validation Log (2026-10-15)

On 2026-10-15, the developer manually executed and validated the complete 8-step live demonstration against the running PostgreSQL 16 container and Spring Boot 3 application under profile `local`:

1. **Step 1 (Ingestion):** Executed `POST /audit/events` with role `local_writer`; received HTTP 201 with `sequenceNo: 2`, `contentHash: 7239413a...`, `previousHash: 9140a12b...`, and `recordHash: d8efdbc5...`.
2. **Step 2 (Query):** Executed `GET /audit/events?resourceType=ACCOUNT&resourceId=ACCT-987654` with role `local_auditor`; received HTTP 200 with `totalElements: 1` and deterministic sequence ordering.
3. **Step 3 (Verify & Tamper):**
   - Verified `status: INTACT` across 2 records.
   - Demonstrated trigger protection: direct `UPDATE` was blocked by `audit_event_reject_update_delete` (`ERROR: audit_event is append-only`).
   - Administratively disabled trigger, modified payload of sequence 2 in PostgreSQL, and re-enabled trigger.
   - Executed `GET /audit/verify`; immediately detected `status: CORRUPTED` with `CONTENT_HASH_MISMATCH` at sequence 2 (`expected: 24dcd350...`, `actual: 7239413a...`).
   - Restored original payload; re-verified `status: INTACT`.
4. **Step 4 (Archival):**
   - Archived event `e6adf233-d9b5-4dc9-8d88-6791c60d0da3` via `POST /audit/archive/{id}` (`HTTP 200`).
   - Default query excluded it (`totalElements: 0`).
   - Query with `includeArchived=true` returned the event with `archivedAt: "2026-10-15T12:37:39.867Z"`.
   - Complete-chain verification confirmed `status: INTACT` across all records with **0 false positives**.
5. **Step 5 (Structured Redaction):**
   - Redacted `accountNumber` on event `532d4da9-de7e-4c47-af02-88049a1f9ad7` via `POST /audit/events/{id}/redact` (`HTTP 200`, `status: COMPLETED`, `redactionType: MASKED`, `metaAuditSequenceNo: 5`).
   - Automatically appended `PAYLOAD_REDACTED` meta-event at sequence 5.
   - Verified query projection masked `accountNumber` as `"[REDACTED]"`.
6. **Step 6 (Export & Python Verifier):**
   - Exported verifiable bundle via `GET /audit/exports?resourceId=ACCT-987654`.
   - Executed standalone Python script `scripts/verify_export.py export_bundle.json`; verified exit code 0 and reported `Status: PARTIALLY_VERIFIED_REDACTED` across 5 linked records, confirming unbroken hash chain linkage while honestly flagging masked payload content.
7. **Step 7 (Regulator Compliance):**
   - Queried account access via `GET /audit/compliance/account-access?accountId=ACCT-987654` using `local_regulator` (`HTTP 200`, `totalElements: 4`).
   - Verified that a `REGULATORY_AUDIT_ACCESSED` supervisory meta-audit event was automatically appended to the chain at sequence 6 with `resourceType = "COMPLIANCE_AUDIT"`.
   - Confirmed supervisory events are excluded from subsequent account query results (preventing query recursion loops).
8. **Step 8 (Security & Least Privilege):**
   - Unauthenticated request returned sanitized `HTTP 401 Unauthorized` with `WWW-Authenticate: Basic realm="AuditLogService"`.
   - Regulator requesting internal audit log (`GET /audit/events`) returned sanitized `HTTP 403 Forbidden`.
   - Request to unmapped route (`GET /audit/nonexistent-route`) returned `HTTP 403 Forbidden` by default deny.

---

## 5. Live Defense Q&A Cheat Sheet

### Q1: Why did you choose RFC 8785 (JCS) instead of standard Jackson serialization?
> *"Standard JSON serialization does not guarantee deterministic key ordering across languages, nor does it define deterministic IEEE-754 float representation, subnormal values, or negative-zero normalization. RFC 8785 defines the exact JSON Canonicalization Scheme standard, ensuring that independent verifiers written in Java, Python, Go, or Rust compute the exact same SHA-256 digest over the same semantic payload."*

### Q2: Why use a single global chain instead of per-account or per-resource chains?
> *"A global chain establishes absolute, verifiable global sequence ordering across all enterprise events. In financial audit systems, regulators care about the sequence of events across accounts (e.g. cross-account wash trading or money movement). Per-resource chains can be modeled as filtered projections over the global chain using our witness-node export mechanism without sacrificing global sequencing."*

### Q3: What is the exact security boundary against a database administrator?
> *"Our system enforces defense-in-depth: append-only triggers prevent normal application updates, and `/audit/verify` detects any unauthorized database modification. However, if a superuser rewrites the entire table and recomputes all hashes from genesis, internal database checks cannot detect that without an external trusted anchor. In enterprise production, we would anchor periodic chain checkpoints in an independently controlled external store, such as an AWS S3 bucket with Object Lock or a signed KMS witness log."*

### Q4: How does your structured redaction prevent breaking the hash chain?
> *"We separate data privacy from cryptographic immutability. Physical rows in `audit_event` are never updated. For envelope-encrypted fields, our pluggable `KeyManager` crypto-shreds the data encryption key, rendering ciphertext mathematically indecipherable while preserving the original ciphertext bytes for exact hash recomputation. For legacy plaintext, we register soft-masking in `audit_event_redaction` and project `[REDACTED]` at query time while the verifier reports `PARTIALLY_VERIFIED_REDACTED`."*
