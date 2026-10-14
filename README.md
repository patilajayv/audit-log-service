# Audit Log Service

This repository contains a Java 17 and Spring Boot 3 prototype for the Audit Log Service engineering assessment.

## Current milestone

Milestone 5 is implemented and committed locally as `53d5bcb` (unpushed to `origin`). The application exposes the `POST /audit/events` REST API backed by `AuditAppendService`, enforcing a 1 MiB request body size limit on declared and chunked streams (HTTP 413), strict duplicate JSON-key rejection (HTTP 400), timestamp normalization to UTC milliseconds, and sanitized error handling without database or stack trace disclosure. Isolated local PostgreSQL 16 smoke tests have passed on `127.0.0.1:5433`.

Subsequent milestones will add the query/verification controllers (`GET /audit/events`, `GET /audit/verify`), Spring Security role authorization (`AUDIT_WRITER`, `AUDITOR`), Scenario B archival and redaction workflows, and verifiable export bundles.

## Prerequisites

- Java 17 JDK for development and validation
- Maven 3.9 or later
- Docker Desktop or compatible container runtime for Testcontainers and Compose

The test suite runs against Java 17. Use a Java 17 JDK when validating this project.

## Build and test

Run the full suite of 88 unit and integration tests:

```bash
mvn test
```

The suite includes 29 canonical hashing unit tests with independent vectors, 18 append integration tests with isolated Testcontainers PostgreSQL, 15 database migration tests, 1 application context test, 18 WebMvc controller slice tests, and 7 end-to-end HTTP/database integration tests.

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
