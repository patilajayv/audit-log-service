package com.example.auditlog.verify;

/**
 * Result of an audit chain integrity verification inspection.
 *
 * <p>Clearly separates declared database chain-head metadata from values actually verified,
 * allowing clients to distinguish between fully intact chains, truncated tails, and
 * intermediate tampering.
 *
 * @param status {@code "INTACT"} if cryptographic verification succeeded completely, or {@code "CORRUPTED"}
 * @param recordsVerified the count of sequential records scanned and verified
 * @param headSequenceNo the sequence number declared in {@code audit_chain_head} (null if head record is missing)
 * @param headRecordHash the record hash declared in {@code audit_chain_head} (null if head record is missing)
 * @param lastVerifiedSequenceNo the sequence number of the last successfully verified record (0 for an empty chain)
 * @param lastVerifiedRecordHash the record hash of the last successfully verified record (genesis hash for an empty chain)
 * @param violation diagnostic details of the first detected inconsistency, or null if intact
 */
public record AuditVerificationResponse(
        String status,
        long recordsVerified,
        Long headSequenceNo,
        String headRecordHash,
        Long lastVerifiedSequenceNo,
        String lastVerifiedRecordHash,
        ChainViolation violation) {

    public static final String STATUS_INTACT = "INTACT";
    public static final String STATUS_CORRUPTED = "CORRUPTED";

    public static AuditVerificationResponse intact(
            long recordsVerified,
            long headSequenceNo,
            String headRecordHash,
            long lastVerifiedSequenceNo,
            String lastVerifiedRecordHash) {
        return new AuditVerificationResponse(
                STATUS_INTACT,
                recordsVerified,
                headSequenceNo,
                headRecordHash,
                lastVerifiedSequenceNo,
                lastVerifiedRecordHash,
                null);
    }

    public static AuditVerificationResponse corrupted(
            long recordsVerified,
            Long headSequenceNo,
            String headRecordHash,
            Long lastVerifiedSequenceNo,
            String lastVerifiedRecordHash,
            ChainViolation violation) {
        return new AuditVerificationResponse(
                STATUS_CORRUPTED,
                recordsVerified,
                headSequenceNo,
                headRecordHash,
                lastVerifiedSequenceNo,
                lastVerifiedRecordHash,
                violation);
    }
}
