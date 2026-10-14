CREATE ROLE audit_app
    LOGIN
    PASSWORD 'local-development-password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

GRANT CONNECT ON DATABASE audit_log TO audit_app;
