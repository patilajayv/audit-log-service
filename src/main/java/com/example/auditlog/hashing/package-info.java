/**
 * Deterministic canonicalization and SHA-256 hashing for the audit event chain.
 *
 * <p>The hash chain uses two hash types:
 * <ol>
 *   <li>{@code content_hash} — SHA-256 of the RFC 8785 (JCS) canonical JSON representation of
 *       the event content fields.
 *   <li>{@code record_hash} — SHA-256 of length-prefixed UTF-8 encoded components binding the
 *       event position in the chain.
 * </ol>
 *
 * <p>The canonical format is documented in {@code docs/ARCHITECTURE.md} and in
 * {@link com.example.auditlog.hashing.AuditHashService}.
 */
package com.example.auditlog.hashing;
