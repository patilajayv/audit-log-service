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

## Prioritized backlog

1. Add detailed requirements, architecture, threat model, and acceptance criteria documentation.
2. Add PostgreSQL runtime configuration and migration tooling.
3. Create immutable event, chain-head, and archive-metadata migrations, indexes, role grants, and append-only protections.
4. Implement canonicalization and hash components with fixed test vectors.
5. Implement transactional append with chain-head locking and persistence tests.
6. Implement the event creation API and validation tests.
7. Implement filtered query and stable pagination.
8. Implement complete-chain verification and direct-database tampering tests.
9. Add Spring Security, role authorization, and security tests.
10. Implement bounded Scenario B archival, redacted projections, and verifiable export.
11. Finalize Scenario C clarification, selected implementation slice, and scope-boundary evidence.
12. Add final setup, test, limitation, AI-traceability, attestation, and live-defense documentation.

## Milestone discipline

Before each commit, inspect the exact diff, run the relevant checks, report actual results, propose a commit message, and wait for approval. Record accepted, modified, and rejected AI suggestions with the related validation and commit in `AI_USAGE_LOG.md`.
