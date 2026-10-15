# Attestation

- Full name: `Ajay Vijay Patil`
- Email address: `patilajayv2201@gmail.com`
- Assignment title: `Interview Assignment: Build an AI-Assisted Software Engineering System - Audit Log Service`
- Repository URL: `https://github.com/patilajayv/audit-log-service.git`
- Working branch: `engineering-hardening`
- Merge commit on `main`: `497c7a7b34eea80555750960f4412bc2bd29cf9f`
- Feature commit: `6bce2b3f1f9c556143b4ea5f2cb35fe39e4a07ba`
- Start date: `2026-10-14`
- Submission date: `2026-10-15`

## Attestation Statement

I, Ajay Vijay Patil, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI assistance.

## Reviewed Scope & Verification Evidence

- **Functional Scope:** Complete implementation of Scenario A (append-only ledger, RFC 8785 canonical hashing, SHA-256 chain, query API, full-chain verification, RBAC), Scenario B (soft archival retention, structured payload redaction via AES-256-GCM envelope crypto-shredding, verifiable bulk exports with hash witnesses, standalone Java and Python verifiers), and Scenario C (regulator account access auditing, server-constrained exports, fail-closed supervisory meta-auditing).
- **Hardening Scope:** Two-tier token-bucket rate limiting (pre-auth IP abuse prevention and post-auth principal metering), client-scoped idempotency with RFC 8785 canonical request hashing and chain-head row locking (`SELECT FOR UPDATE`), Flyway migration V5, and servlet auto-registration disablement.
- **CI/CD Infrastructure:** Official Apache Maven 3.9.9 wrapper (`mvnw`, `mvnw.cmd`), automated GitHub Actions CI pipeline (`.github/workflows/ci.yml`), and JaCoCo coverage enforcement.
- **Automated Test Evidence:** 304 automated tests across 25 test classes with 0 failures, 0 errors, and 0 skipped.
- **Code Coverage Evidence:** JaCoCo report: **89.91% instruction coverage** (6,653 / 7,400 instructions), **89.78% line coverage** (1,572 / 1,751 lines), and **72.27% branch coverage** (503 / 696 branches).
- **CI Build Status:** GitHub Actions workflow passed on merge commit `497c7a7`, verifying clean compile, full test execution against Testcontainers PostgreSQL, and coverage report generation.
