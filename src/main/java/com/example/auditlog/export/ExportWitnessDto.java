package com.example.auditlog.export;

/**
 * Hash-only witness node for intermediate, non-matching records in the hash chain.
 *
 * <p>Discloses zero sensitive plaintext payloads, actor IDs, or resource IDs,
 * while providing the necessary hashes to recalculate the unbroken chain from
 * genesis ($0^{64}$) to the observed chain head.
 */
public record ExportWitnessDto(
        long sequenceNo,
        String previousHash,
        String contentHash,
        String recordHash) {
}
