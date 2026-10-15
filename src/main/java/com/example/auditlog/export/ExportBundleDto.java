package com.example.auditlog.export;

import java.util.List;
import java.util.UUID;

/**
 * Self-contained, versioned, independently verifiable bulk export bundle.
 *
 * <p>Enables an external recipient to independently verify the authenticity and integrity
 * of matched audit events by recomputing canonical content hashes and linking the unbroken
 * chain from genesis ($0^{64}$) through intermediate witness nodes to {@code chainHead}.
 */
public record ExportBundleDto(
        String bundleVersion,
        UUID exportId,
        String exportedAt,
        ExportFilterDto filter,
        ExportChainHeadDto chainHead,
        ExportSummaryDto summary,
        List<ExportEventDto> events,
        List<ExportWitnessDto> witnesses) {
}
