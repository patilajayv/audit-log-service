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

## Prioritized backlog

1. Add detailed requirements, architecture, threat model, and acceptance criteria documentation.
2. Implement the deferred Scenario B archive-metadata migration and archival workflow.
3. Implement canonicalization and hash components with fixed test vectors.
4. Implement transactional append with chain-head locking and persistence tests.
5. Implement the event creation API and validation tests.
6. Implement filtered query and stable pagination.
7. Implement complete-chain verification and direct-database tampering tests.
8. Add Spring Security, role authorization, and security tests.
9. Implement bounded Scenario B archival, redacted projections, and verifiable export.
10. Finalize Scenario C clarification, selected implementation slice, and scope-boundary evidence.
11. Add final setup, test, limitation, AI-traceability, attestation, and live-defense documentation.

## Milestone discipline

Before each commit, inspect the exact diff, run the relevant checks, report actual results, propose a commit message, and wait for approval. Record accepted, modified, and rejected AI suggestions with the related validation and commit in `AI_USAGE_LOG.md`.
