package com.example.auditlog.export;

/**
 * Summary statistics of the export bundle.
 */
public record ExportSummaryDto(
        long matchedEventsCount,
        Long firstMatchedSequenceNo,
        Long lastMatchedSequenceNo,
        long witnessCount) {
}
