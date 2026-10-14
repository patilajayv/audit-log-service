package com.example.auditlog.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
class FlywayMigrationIntegrationTests {

    private static final String APPLICATION_PASSWORD = "local-development-password";
    private static final String GENESIS_HASH = "0".repeat(64);
    private static final String FIRST_RECORD_HASH = "b".repeat(64);
    private static final String OTHER_HASH = "c".repeat(64);
    private static final String CONCURRENT_WINNER_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String CONCURRENT_LOSER_HASH = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private static final Duration CONCURRENCY_TIMEOUT = Duration.ofSeconds(5);

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static Flyway flyway;

    @BeforeAll
    static void createApplicationRole() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE ROLE audit_app LOGIN PASSWORD '" + APPLICATION_PASSWORD + "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT");
        }

        flyway = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .cleanDisabled(false)
                .load();
    }

    @BeforeEach
    void migrateCleanDatabase() {
        flyway.clean();
        flyway.migrate();
    }

    @Test
    void migrationCreatesGenesisChainHead() throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong("last_sequence_no")).isZero();
            assertThat(result.getString("last_record_hash")).isEqualTo(GENESIS_HASH);
        }
    }

    @Test
    void v2MigratesAValidV1GenesisChain() throws SQLException {
        migrateV1Only();

        migrateV2();

        assertChainHead(0, GENESIS_HASH);
        assertV2EnforcementInstalled();
    }

    @Test
    void v2RejectsAV1OrphanEventAndRollsBackEnforcementInstallation() throws SQLException {
        migrateV1Only();
        try (Connection connection = connection()) {
            insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
        }

        assertV2MigrationRejected();
        assertEventCount(1);
        assertChainHead(0, GENESIS_HASH);
    }

    @Test
    void v2RejectsAV1BrokenPreviousHashLinkAndRollsBackEnforcementInstallation() throws SQLException {
        migrateV1Only();
        try (Connection connection = connection()) {
            insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
            advanceHead(connection, 1, FIRST_RECORD_HASH);
            insertEvent(connection, 2, OTHER_HASH, CONCURRENT_WINNER_HASH);
        }

        assertV2MigrationRejected();
        assertEventCount(2);
        assertChainHead(1, FIRST_RECORD_HASH);
    }

    @Test
    void v2RejectsAV1HeadHashMismatchAndRollsBackEnforcementInstallation() throws SQLException {
        migrateV1Only();
        try (Connection connection = connection()) {
            insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
            advanceHead(connection, 1, OTHER_HASH);
        }

        assertV2MigrationRejected();
        assertEventCount(1);
        assertChainHead(1, OTHER_HASH);
    }

    @Test
    void v2RejectsAV1HeadSequenceMismatchAndRollsBackEnforcementInstallation() throws SQLException {
        migrateV1Only();
        try (Connection connection = connection()) {
            insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
            advanceHead(connection, 1, FIRST_RECORD_HASH);
            advanceHead(connection, 2, OTHER_HASH);
        }

        assertV2MigrationRejected();
        assertEventCount(1);
        assertChainHead(2, OTHER_HASH);
    }

    @Test
    void migrationAllowsLinkedEventAndHeadAdvancementInOneTransaction() throws SQLException {
        try (Connection connection = connection()) {
            appendEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
        }

        assertChainHead(1, FIRST_RECORD_HASH);
    }

    @Test
    void migrationRejectsHeadAdvanceWithoutMatchingEvent() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("UPDATE audit_chain_head SET last_sequence_no = 1, last_record_hash = repeat('b', 64) WHERE chain_id = 1"));

            assertThat(exception.getSQLState()).isEqualTo("55000");
        }

        assertChainHead(0, GENESIS_HASH);
    }

    @Test
    void migrationRejectsHeadAdvanceWithArbitraryHashAndRollsBackEvent() throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> advanceHead(connection, 1, OTHER_HASH));

            assertThat(exception.getSQLState()).isEqualTo("55000");
            connection.rollback();
        }

        assertChainHead(0, GENESIS_HASH);
        assertEventCount(0);
    }

    @Test
    void migrationRejectsEventWithIncorrectPreviousHash() throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);

            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertEvent(connection, 1, OTHER_HASH, FIRST_RECORD_HASH));

            assertThat(exception.getSQLState()).isEqualTo("55000");
            connection.rollback();
        }

        assertEventCount(0);
    }

    @Test
    void migrationRejectsSequenceJumps() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("UPDATE audit_chain_head SET last_sequence_no = 2, last_record_hash = repeat('b', 64) WHERE chain_id = 1"));

            assertThat(exception.getSQLState()).isEqualTo("55000");
        }

        assertChainHead(0, GENESIS_HASH);
    }

    @Test
    void migrationRejectsEventWithoutSameTransactionHeadAdvance() throws SQLException {
        try (Connection connection = connection()) {
            SQLException exception = assertThrows(
                    SQLException.class,
                    () -> insertEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH));

            assertThat(exception.getSQLState()).isEqualTo("55000");
        }

        assertChainHead(0, GENESIS_HASH);
        assertEventCount(0);
    }

    @Test
    void migrationRejectsUpdatesDeletesAndTruncatesOfAuditEvents() throws SQLException {
        try (Connection connection = connection()) {
            appendEvent(connection, 1, GENESIS_HASH, FIRST_RECORD_HASH);
        }

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            SQLException updateException = assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("UPDATE audit_event SET event_type = 'TAMPERED' WHERE sequence_no = 1"));
            SQLException deleteException = assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("DELETE FROM audit_event WHERE sequence_no = 1"));
            SQLException truncateException = assertThrows(
                    SQLException.class,
                    () -> statement.executeUpdate("TRUNCATE audit_event"));

            assertThat(updateException.getSQLState()).isEqualTo("55000");
            assertThat(deleteException.getSQLState()).isEqualTo("55000");
            assertThat(truncateException.getSQLState()).isEqualTo("55000");
        }
    }

    @Test
    void migrationGrantsTheApplicationRoleOnlyRequiredTablePrivileges() throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT
                            has_table_privilege('audit_app', 'audit_event', 'SELECT') AS can_select_event,
                            has_table_privilege('audit_app', 'audit_event', 'INSERT') AS can_insert_event,
                            has_table_privilege('audit_app', 'audit_event', 'UPDATE') AS can_update_event,
                            has_table_privilege('audit_app', 'audit_event', 'DELETE') AS can_delete_event,
                            has_table_privilege('audit_app', 'audit_event', 'TRUNCATE') AS can_truncate_event,
                            has_table_privilege('audit_app', 'audit_chain_head', 'SELECT') AS can_select_head,
                            has_table_privilege('audit_app', 'audit_chain_head', 'UPDATE') AS can_update_head
                        """)) {
            assertThat(result.next()).isTrue();
            assertThat(result.getBoolean("can_select_event")).isTrue();
            assertThat(result.getBoolean("can_insert_event")).isTrue();
            assertThat(result.getBoolean("can_update_event")).isFalse();
            assertThat(result.getBoolean("can_delete_event")).isFalse();
            assertThat(result.getBoolean("can_truncate_event")).isFalse();
            assertThat(result.getBoolean("can_select_head")).isTrue();
            assertThat(result.getBoolean("can_update_head")).isTrue();
        }
    }

    @Test
    void concurrentAppendsCannotCommitDuplicateSequenceNumbersOrDivergeTheChainHead() throws Exception {
        CountDownLatch winnerInsertedEvent = new CountDownLatch(1);
        CountDownLatch loserStartedAppend = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try (Connection winner = connection()) {
            winner.setAutoCommit(false);
            insertEvent(winner, 1, GENESIS_HASH, CONCURRENT_WINNER_HASH, UUID.randomUUID());
            winnerInsertedEvent.countDown();

            Future<AppendAttempt> loserAttempt = executor.submit(() -> {
                try (Connection loser = connection()) {
                    loser.setAutoCommit(false);
                    setLockTimeout(loser);
                    assertThat(winnerInsertedEvent.await(CONCURRENCY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)).isTrue();
                    loserStartedAppend.countDown();

                    try {
                        insertEvent(loser, 1, GENESIS_HASH, CONCURRENT_LOSER_HASH, UUID.randomUUID());
                        advanceHead(loser, 1, CONCURRENT_LOSER_HASH);
                        loser.commit();
                        return AppendAttempt.success();
                    } catch (SQLException exception) {
                        loser.rollback();
                        return AppendAttempt.failure(exception.getSQLState());
                    }
                }
            });

            assertThat(loserStartedAppend.await(CONCURRENCY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)).isTrue();
            AppendAttempt outcome = loserAttempt.get(CONCURRENCY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            assertThat(outcome.committed()).isFalse();
            assertThat(outcome.sqlState()).isEqualTo("55P03");

            advanceHead(winner, 1, CONCURRENT_WINNER_HASH);
            winner.commit();
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(CONCURRENCY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)).isTrue();
        }

        assertContiguousChainWithHead(1, CONCURRENT_WINNER_HASH);
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static void migrateV1Only() {
        flyway.clean();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .target("1")
                .cleanDisabled(false)
                .load()
                .migrate();
    }

    private static void migrateV2() {
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
    }

    private static void assertV2MigrationRejected() throws SQLException {
        assertThatThrownBy(FlywayMigrationIntegrationTests::migrateV2)
                .hasMessageContaining("existing audit-chain data is inconsistent");
        assertV2EnforcementNotInstalled();
        assertNoSuccessfulV2HistoryEntry();
    }

    private static void appendEvent(Connection connection, long sequenceNo, String previousHash, String recordHash) throws SQLException {
        connection.setAutoCommit(false);
        try {
            insertEvent(connection, sequenceNo, previousHash, recordHash);
            advanceHead(connection, sequenceNo, recordHash);
            connection.commit();
        } catch (SQLException exception) {
            connection.rollback();
            throw exception;
        }
    }

    private static void insertEvent(Connection connection, long sequenceNo, String previousHash, String recordHash) throws SQLException {
        insertEvent(connection, sequenceNo, previousHash, recordHash,
                UUID.fromString(String.format("00000000-0000-0000-0000-%012d", sequenceNo)));
    }

    private static void insertEvent(Connection connection, long sequenceNo, String previousHash, String recordHash, UUID eventId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO audit_event (
                    sequence_no, event_id, event_type, actor_id, resource_type, resource_id, payload,
                    recorded_at, canonicalization_version, content_hash, previous_hash, record_hash
                ) VALUES (?, ?, 'USER_LOGIN', 'actor-1', 'ACCOUNT', 'account-1', '{}'::jsonb,
                    TIMESTAMPTZ '2026-10-14 00:00:00+00', 'JCS-1', repeat('a', 64), ?, ?)
                """)) {
            statement.setLong(1, sequenceNo);
            statement.setObject(2, eventId);
            statement.setString(3, previousHash);
            statement.setString(4, recordHash);
            statement.executeUpdate();
        }
    }

    private static void advanceHead(Connection connection, long sequenceNo, String recordHash) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE audit_chain_head
                SET last_sequence_no = ?, last_record_hash = ?
                WHERE chain_id = 1
                """)) {
            statement.setLong(1, sequenceNo);
            statement.setString(2, recordHash);
            statement.executeUpdate();
        }
    }

    private static void setLockTimeout(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET LOCAL lock_timeout = '1s'");
        }
    }

    private static void assertChainHead(long expectedSequenceNo, String expectedHash) throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT last_sequence_no, last_record_hash FROM audit_chain_head WHERE chain_id = 1")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong("last_sequence_no")).isEqualTo(expectedSequenceNo);
            assertThat(result.getString("last_record_hash")).isEqualTo(expectedHash);
        }
    }

    private static void assertEventCount(long expectedCount) throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT count(*) FROM audit_event")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong(1)).isEqualTo(expectedCount);
        }
    }

    private static void assertV2EnforcementInstalled() throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT count(*)
                        FROM pg_trigger
                        WHERE tgname IN ('audit_event_enforce_append', 'audit_event_requires_chain_head_advance')
                          AND NOT tgisinternal
                        """)) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong(1)).isEqualTo(2);
        }
    }

    private static void assertV2EnforcementNotInstalled() throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT count(*)
                        FROM pg_trigger
                        WHERE tgname IN ('audit_event_enforce_append', 'audit_event_requires_chain_head_advance')
                          AND NOT tgisinternal
                        """)) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong(1)).isZero();
        }

        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT to_regprocedure('enforce_audit_event_append()') IS NULL
                            AND to_regprocedure('require_audit_event_chain_head_advance()') IS NULL
                        """)) {
            assertThat(result.next()).isTrue();
            assertThat(result.getBoolean(1)).isTrue();
        }
    }

    private static void assertNoSuccessfulV2HistoryEntry() throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT count(*)
                        FROM flyway_schema_history
                        WHERE version = '2' AND success
                        """)) {
            assertThat(result.next()).isTrue();
            assertThat(result.getLong(1)).isZero();
        }
    }

    private static void assertContiguousChainWithHead(long expectedLastSequence, String expectedLastHash) throws SQLException {
        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet count = statement.executeQuery("SELECT count(*), count(DISTINCT sequence_no) FROM audit_event")) {
            assertThat(count.next()).isTrue();
            assertThat(count.getLong(1)).isEqualTo(expectedLastSequence);
            assertThat(count.getLong(2)).isEqualTo(expectedLastSequence);
        }

        try (Connection connection = connection();
                Statement statement = connection.createStatement();
                ResultSet events = statement.executeQuery("SELECT sequence_no, previous_hash, record_hash FROM audit_event ORDER BY sequence_no")) {
            long expectedSequence = 1;
            String expectedPreviousHash = GENESIS_HASH;
            while (events.next()) {
                assertThat(events.getLong("sequence_no")).isEqualTo(expectedSequence++);
                assertThat(events.getString("previous_hash")).isEqualTo(expectedPreviousHash);
                expectedPreviousHash = events.getString("record_hash");
            }
            assertThat(expectedSequence - 1).isEqualTo(expectedLastSequence);
            assertThat(expectedPreviousHash).isEqualTo(expectedLastHash);
        }

        assertChainHead(expectedLastSequence, expectedLastHash);
    }

    private record AppendAttempt(boolean committed, String sqlState) {
        private static AppendAttempt success() {
            return new AppendAttempt(true, null);
        }

        private static AppendAttempt failure(String sqlState) {
            return new AppendAttempt(false, sqlState);
        }
    }
}
