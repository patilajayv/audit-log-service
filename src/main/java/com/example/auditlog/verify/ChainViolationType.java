package com.example.auditlog.verify;

/**
 * Enumeration of audit chain consistency and cryptographic violation types.
 */
public enum ChainViolationType {
    /**
     * The first event does not use the 64-character all-zero genesis hash as previous_hash.
     */
    GENESIS_MISMATCH,

    /**
     * Sequence numbers are not contiguous or do not start at sequence 1.
     */
    SEQUENCE_GAP,

    /**
     * The stored content_hash does not match the recomputed RFC 8785 canonical hash.
     */
    CONTENT_HASH_MISMATCH,

    /**
     * An event's previous_hash does not match the record_hash of the preceding event.
     */
    PREVIOUS_HASH_MISMATCH,

    /**
     * The stored record_hash does not match the recomputed record hash.
     */
    RECORD_HASH_MISMATCH,

    /**
     * The audit_chain_head sequence number or record hash does not match the verified chain tail.
     */
    CHAIN_HEAD_MISMATCH
}
