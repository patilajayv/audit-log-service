# Audit Log Service

This repository contains a Java 17 and Spring Boot 3 prototype for the Audit Log Service engineering assessment.

## Current milestone

The project foundation provides a minimal Spring Boot application, a context-load test, and local PostgreSQL configuration. Audit event APIs, persistence, hashing, security, and migrations are added in later milestones.

## Prerequisites

- Java 17 JDK for development and final validation
- Maven 3.9 or later
- Docker Desktop with Docker Compose

The current workstation runs Maven with JDK 24. Maven compiles this project with Java 17 compatibility through the Spring Boot `java.version` setting. Install and select a Java 17 JDK before final validation and submission.

## Build and test

```bash
mvn test
```

## Local PostgreSQL

```bash
docker compose up -d
```

The Compose credentials are for local development only. Runtime database configuration and migrations will be added with the persistence milestone.

## Repository scope

The confidential assignment PDF remains outside this repository and must not be committed or pushed.
