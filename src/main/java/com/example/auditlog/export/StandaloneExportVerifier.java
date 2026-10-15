package com.example.auditlog.export;

import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.hashing.CanonicalEventContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Independent cryptographic verifier for bulk audit export bundles.
 *
 * <p>Validates:
 * <ol>
 *   <li>Sequence contiguity from genesis (sequence 1) to {@code chainHead.sequenceNo}.</li>
 *   <li>Genesis hash linkage at sequence 1.</li>
 *   <li>Previous-hash pointer linkage across all intermediate sequences.</li>
 *   <li>RFC 8785 (JCS-1) canonical content hash recalculation for all matched events.</li>
 *   <li>Domain-separated SHA-256 record hash recalculation for all records (events and witnesses).</li>
 *   <li>Tail alignment of the recomputed record hash against {@code chainHead.recordHash}.</li>
 *   <li>Conformance of all exported events to the declared filter criteria.</li>
 * </ol>
 */
public class StandaloneExportVerifier {

    public enum Status {
        INTACT,
        PARTIALLY_VERIFIED_REDACTED,
        CORRUPTED
    }

    public record ExportVerificationResult(
            Status status,
            long recordsVerified,
            long matchedEventsVerified,
            long maskedEventsCount,
            Long failureSequenceNo,
            String failureReason) {

        public static ExportVerificationResult intact(long recordsVerified, long matchedEventsVerified) {
            return new ExportVerificationResult(Status.INTACT, recordsVerified, matchedEventsVerified, 0L, null, null);
        }

        public static ExportVerificationResult partiallyVerifiedRedacted(
                long recordsVerified,
                long matchedEventsVerified,
                long maskedEventsCount) {
            return new ExportVerificationResult(
                    Status.PARTIALLY_VERIFIED_REDACTED,
                    recordsVerified,
                    matchedEventsVerified,
                    maskedEventsCount,
                    null,
                    null);
        }

        public static ExportVerificationResult corrupted(long failureSequenceNo, String reason) {
            return new ExportVerificationResult(Status.CORRUPTED, 0L, 0L, 0L, failureSequenceNo, reason);
        }
    }

    private final AuditHashService hashService;

    public StandaloneExportVerifier() {
        this.hashService = new AuditHashService();
    }

    public StandaloneExportVerifier(AuditHashService hashService) {
        this.hashService = hashService;
    }

    /**
     * Verifies the cryptographic integrity and filter compliance of an export bundle.
     *
     * @param bundle the bundle to verify
     * @return {@link ExportVerificationResult} indicating {@code INTACT} or {@code CORRUPTED}
     */
    public ExportVerificationResult verify(ExportBundleDto bundle) {
        if (bundle == null) {
            return ExportVerificationResult.corrupted(0L, "Export bundle is null");
        }
        if (bundle.chainHead() == null) {
            return ExportVerificationResult.corrupted(0L, "Bundle is missing chainHead checkpoint");
        }

        long headSeq = bundle.chainHead().sequenceNo();
        String headHash = bundle.chainHead().recordHash();

        if (headSeq < 0L) {
            return ExportVerificationResult.corrupted(headSeq, "Invalid chain head sequence number: " + headSeq);
        }

        if (headSeq == 0L) {
            if (!AuditHashService.GENESIS_HASH.equals(headHash)) {
                return ExportVerificationResult.corrupted(0L, "Empty chain head hash must equal genesis hash");
            }
            if ((bundle.events() != null && !bundle.events().isEmpty())
                    || (bundle.witnesses() != null && !bundle.witnesses().isEmpty())) {
                return ExportVerificationResult.corrupted(0L, "Empty chain must contain 0 events and 0 witnesses");
            }
            return ExportVerificationResult.intact(0L, 0L);
        }

        if (bundle.events() == null) {
            return ExportVerificationResult.corrupted(0L, "Bundle events list is null");
        }
        if (bundle.witnesses() == null) {
            return ExportVerificationResult.corrupted(0L, "Bundle witnesses list is null");
        }

        // Merge matched events and witnesses into sequence map
        Map<Long, ExportEventDto> eventMap = new HashMap<>();
        Map<Long, ExportWitnessDto> witnessMap = new HashMap<>();

        for (ExportEventDto ev : bundle.events()) {
            if (ev == null) {
                return ExportVerificationResult.corrupted(0L, "Event record is null");
            }
            if (ev.sequenceNo() < 1L || ev.sequenceNo() > headSeq) {
                return ExportVerificationResult.corrupted(
                        ev.sequenceNo(),
                        "Event sequence number " + ev.sequenceNo() + " is outside valid range [1, " + headSeq + "]");
            }
            if (eventMap.put(ev.sequenceNo(), ev) != null) {
                return ExportVerificationResult.corrupted(ev.sequenceNo(), "Duplicate event sequence number: " + ev.sequenceNo());
            }
        }

        for (ExportWitnessDto wt : bundle.witnesses()) {
            if (wt == null) {
                return ExportVerificationResult.corrupted(0L, "Witness record is null");
            }
            if (wt.sequenceNo() < 1L || wt.sequenceNo() > headSeq) {
                return ExportVerificationResult.corrupted(
                        wt.sequenceNo(),
                        "Witness sequence number " + wt.sequenceNo() + " is outside valid range [1, " + headSeq + "]");
            }
            if (witnessMap.put(wt.sequenceNo(), wt) != null) {
                return ExportVerificationResult.corrupted(wt.sequenceNo(), "Duplicate witness sequence number: " + wt.sequenceNo());
            }
            if (eventMap.containsKey(wt.sequenceNo())) {
                return ExportVerificationResult.corrupted(wt.sequenceNo(), "Sequence number appears in both events and witnesses: " + wt.sequenceNo());
            }
        }

        // Validate filter criteria conformance
        String filterType = bundle.filter() != null ? bundle.filter().filterType() : null;
        String filterValue = bundle.filter() != null ? bundle.filter().filterValue() : null;

        for (ExportEventDto ev : bundle.events()) {
            if ("ACTOR_ID".equalsIgnoreCase(filterType)) {
                if (!Objects.equals(ev.actorId(), filterValue)) {
                    return ExportVerificationResult.corrupted(
                            ev.sequenceNo(),
                            "Event actorId '" + ev.actorId() + "' does not match filter '" + filterValue + "'");
                }
            } else if ("RESOURCE_ID".equalsIgnoreCase(filterType)) {
                if (!Objects.equals(ev.resourceId(), filterValue)) {
                    return ExportVerificationResult.corrupted(
                            ev.sequenceNo(),
                            "Event resourceId '" + ev.resourceId() + "' does not match filter '" + filterValue + "'");
                }
            }
        }

        // Sequential cryptographic verification from sequence 1 to headSeq
        String previousHash = AuditHashService.GENESIS_HASH;
        long recordsVerified = 0L;
        long matchedEventsVerified = 0L;
        long maskedEventsCount = 0L;

        for (long seq = 1L; seq <= headSeq; seq++) {
            ExportEventDto event = eventMap.get(seq);
            ExportWitnessDto witness = witnessMap.get(seq);

            if (event == null && witness == null) {
                return ExportVerificationResult.corrupted(seq, "Sequence gap: sequence " + seq + " is missing from bundle");
            }

            String storedPrevHash;
            String contentHash;
            String storedRecordHash;

            if (event != null) {
                storedPrevHash = event.previousHash();
                contentHash = event.contentHash();
                storedRecordHash = event.recordHash();

                boolean isMasked = "MASKED".equalsIgnoreCase(event.redactionType());
                if (isMasked) {
                    // Legacy masked event: original plaintext is omitted from the export projection.
                    // Recalculating content hash against the masked JSON cannot match the stored ingestion hash.
                    // We verify chain linkage and record-hash commitments using the stored content_hash,
                    // but distinguish this from fully verified payload content.
                    maskedEventsCount++;
                } else {
                    // Full content verification: unredacted events and crypto-shredded envelopes
                    try {
                        Instant sourceInstant = event.sourceTimestamp() != null
                                ? Instant.parse(event.sourceTimestamp()).truncatedTo(ChronoUnit.MILLIS)
                                : null;
                        Instant recordedInstant = event.recordedAt() != null
                                ? Instant.parse(event.recordedAt()).truncatedTo(ChronoUnit.MILLIS)
                                : null;

                        CanonicalEventContent content = new CanonicalEventContent(
                                event.canonicalizationVersion(),
                                event.eventId(),
                                event.eventType(),
                                event.actorId(),
                                event.resourceType(),
                                event.resourceId(),
                                event.payload(),
                                sourceInstant,
                                recordedInstant);

                        String recomputedContentHash = hashService.computeContentHash(content);
                        if (!recomputedContentHash.equalsIgnoreCase(contentHash)) {
                            return ExportVerificationResult.corrupted(
                                    seq,
                                    "Content hash mismatch at sequence " + seq + ": stored=" + contentHash
                                            + ", recomputed=" + recomputedContentHash);
                        }
                    } catch (Exception e) {
                        return ExportVerificationResult.corrupted(
                                seq,
                                "Failed to canonicalize payload at sequence " + seq + ": " + e.getMessage());
                    }
                    matchedEventsVerified++;
                }
            } else {
                storedPrevHash = witness.previousHash();
                contentHash = witness.contentHash();
                storedRecordHash = witness.recordHash();
            }

            // Check previous hash linkage
            if (!previousHash.equalsIgnoreCase(storedPrevHash)) {
                return ExportVerificationResult.corrupted(
                        seq,
                        "Previous hash mismatch at sequence " + seq + ": expected=" + previousHash
                                + ", actual=" + storedPrevHash);
            }

            // Recalculate record hash
            String recomputedRecordHash = hashService.computeRecordHash(seq, storedPrevHash, contentHash);
            if (!recomputedRecordHash.equalsIgnoreCase(storedRecordHash)) {
                return ExportVerificationResult.corrupted(
                        seq,
                        "Record hash mismatch at sequence " + seq + ": stored=" + storedRecordHash
                                + ", recomputed=" + recomputedRecordHash);
            }

            previousHash = storedRecordHash;
            recordsVerified++;
        }

        if ((long) eventMap.size() + (long) witnessMap.size() != headSeq) {
            return ExportVerificationResult.corrupted(
                    headSeq,
                    "Total records in bundle (" + (eventMap.size() + witnessMap.size()) + ") does not match chain head sequence (" + headSeq + ")");
        }

        // Final chain head alignment check
        if (!previousHash.equalsIgnoreCase(headHash)) {
            return ExportVerificationResult.corrupted(
                    headSeq,
                    "Chain head record hash mismatch: expected=" + headHash + ", computed=" + previousHash);
        }

        if (maskedEventsCount > 0) {
            return ExportVerificationResult.partiallyVerifiedRedacted(
                    recordsVerified, matchedEventsVerified, maskedEventsCount);
        }

        return ExportVerificationResult.intact(recordsVerified, matchedEventsVerified);
    }
}
