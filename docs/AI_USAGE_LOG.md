# AI Usage Log

This log records AI-assisted work honestly. Each future entry will identify the task, prompt or context summary, AI output used, human decisions, modifications or rejections, validation performed, and related commit.

## 2026-10-14 - Milestone 1 foundation

- **Task:** Create the initial Maven, Spring Boot, Docker Compose, test, and setup-documentation foundation.
- **AI contribution:** Drafted the proposed file structure and starter configuration from the approved technology stack and milestone scope.
- **Engineer oversight:** The user constrained the repository location, prohibited including the assignment PDF, and required review before committing.
- **Decision:** Pending user review. No commit has been made.
- **Validation:** `mvn -Dmaven.repo.local=/private/tmp/audit-log-service-m2 test` passed: 1 test run, 0 failures, 0 errors, 0 skipped. `docker compose config` passed. `git diff --check` passed.
