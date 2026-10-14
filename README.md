# Audit Log Service

This repository contains a Java 17 and Spring Boot 3 prototype for the Audit Log Service engineering assessment.

## Current milestone

Milestone 4 is complete. The application layer provides deterministic RFC 8785 (JCS) canonical JSON hashing (`content_hash`), 4-byte big-endian length-prefixed domain-separated chain linking (`record_hash`), and a transactional `AuditAppendService` that locks `audit_chain_head` (`SELECT ... FOR UPDATE`), assigns monotonic sequences, inserts events, and advances the chain head atomically.

Subsequent milestones will add the REST write/query/verification controllers, Spring Security role authorization, Scenario B archival and redaction workflows, and verifiable export bundles.

## Prerequisites

- Java 17 JDK for development and validation
- Maven 3.9 or later
- Docker Desktop or compatible container runtime for Testcontainers and Compose

The test suite runs against Java 17. Use a Java 17 JDK when validating this project.

## Build and test

Run the full suite of 63 unit and integration tests:

```bash
mvn test
```

The suite includes 29 canonical hashing unit tests with independent vectors, 18 append integration tests with isolated Testcontainers PostgreSQL, 15 database migration tests, and 1 application context test.

## Local PostgreSQL

```bash
docker compose up -d
```

The Compose credentials are for local development only. PostgreSQL is published only on `127.0.0.1:5432`, so the local profile continues to use `localhost`. The container bootstrap creates the limited `audit_app` role, while `audit_migrator` owns schema migration. Start the application with the local profile to run Flyway migrations:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

## Repository scope

The confidential assignment PDF remains outside this repository and must not be committed or pushed.
