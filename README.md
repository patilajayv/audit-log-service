# Audit Log Service

This repository contains a Java 17 and Spring Boot 3 prototype for the Audit Log Service engineering assessment.

## Current milestone

Milestone 9 is implemented (changes uncommitted locally pending review). The application implements Scenario B retention and soft-archival metadata management, Flyway V3 schema migration, atomic and idempotent single-event and batch archival endpoints, configurable retention window, query filtering (`includeArchived`), and complete-chain verification preservation:
- `POST /audit/events`: requires role `AUDIT_WRITER`
- `POST /audit/archive/{eventId}`: requires role `AUDIT_WRITER`
- `POST /audit/archive/eligible`: requires role `AUDIT_WRITER`
- `GET /audit/events`: requires role `AUDITOR`
- `GET /audit/verify`: requires role `AUDITOR`
- All other routes are denied by default.

Unauthenticated requests receive a sanitized HTTP 401 `ErrorResponse` preserving the `WWW-Authenticate: Basic realm="AuditLogService"` header. Insufficiently privileged requests receive a sanitized HTTP 403 `ErrorResponse`. Milestone 8 (security and authentication) is committed locally as `d69a172`, Milestone 7 (`GET /audit/verify`) is committed as `01d5460`, Milestone 6 (`GET /audit/events`) is committed as `b9739f0`, and Milestone 5 (`POST /audit/events`) is committed as `53d5bcb`.

Subsequent milestones will add remaining Scenario B payload redaction workflows and verifiable export bundles (`GET /audit/exports`).

## Prerequisites

- Java 17 JDK for development and validation
- Maven 3.9 or later
- Docker Desktop or compatible container runtime for Testcontainers and Compose

The test suite runs against Java 17. Use a Java 17 JDK when validating this project.

## Build and test

Run the full suite of 177 unit and integration tests:

```bash
mvn test
```

The suite includes 29 canonical hashing unit tests with independent vectors, 18 append integration tests with isolated Testcontainers PostgreSQL, 17 database migration tests, 1 application context test, 18 append WebMvc controller slice tests, 7 append end-to-end HTTP/database integration tests, 10 query WebMvc controller slice tests, 13 query end-to-end HTTP/database integration tests, 3 verify WebMvc controller slice tests, 16 verify/tamper end-to-end HTTP/database integration tests, 18 security/authorization end-to-end HTTP/database integration tests, 7 security credential validation unit/context tests, 5 archival WebMvc controller slice tests, 6 retention configuration validation tests, and 9 archival service/database integration tests.

## Local PostgreSQL

Start the local PostgreSQL 16 container:

```bash
docker compose up -d
```

The Compose credentials are for local development only. PostgreSQL defaults to `127.0.0.1:5432`. If port 5432 is already occupied by a host database (such as a native PostgreSQL service), an isolated port mapping can be configured locally by creating a git-excluded `compose.override.yaml`:

```yaml
services:
  postgres:
    ports: !override
      - "127.0.0.1:5433:5432"
```

*(Note: `compose.override.yaml` is local-only and must be created separately on another clone if port 5432 is occupied).*

The container bootstrap creates the limited `audit_app` role, while `audit_migrator` owns schema migration. Start the application with the `local` profile to run Flyway migrations:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

When running on an alternate port such as `5433`:

```bash
AUDIT_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
AUDIT_MIGRATOR_DB_URL=jdbc:postgresql://localhost:5433/audit_log \
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

## Repository scope

The confidential assignment PDF remains outside this repository and must not be committed or pushed.
