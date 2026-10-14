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
