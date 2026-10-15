package com.example.auditlog.export;

/**
 * Observed chain-head state committed at the time the export snapshot was acquired.
 *
 * <p>Note: This checkpoint proves relative internal consistency of the exported ledger slice.
 * External verification against ledger history rewriting requires an out-of-band anchor.
 */
public record ExportChainHeadDto(
        long sequenceNo,
        String recordHash) {
}
