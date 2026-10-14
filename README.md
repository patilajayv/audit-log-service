# Audit Log Service

This repository contains a Java 17 and Spring Boot 3 prototype for the Audit Log Service engineering assessment.

## Current milestone

The project foundation provides a minimal Spring Boot application, a context-load test, local PostgreSQL configuration, and Flyway database migrations. Audit event APIs, hashing, and security are added in later milestones.

## Prerequisites

- Java 17 JDK for development and final validation
- Maven 3.9 or later
- Docker Desktop with Docker Compose

The latest Maven test run on this workstation used Java 17.0.16. Other developer workstations may use different Java runtimes; use a Java 17 JDK when validating this project.

## Build and test

```bash
mvn test
```

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
