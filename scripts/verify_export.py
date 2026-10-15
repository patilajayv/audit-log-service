#!/usr/bin/env python3
"""
Standalone independent verification script for Charles Schwab FDE Audit Log Export Bundles.

Verifies:
1. Sequence contiguity from sequence 1 (genesis) to chainHead.sequenceNo without gaps or duplicates.
2. Genesis previous-hash linkage (64 zeros) at sequence 1.
3. Previous-hash linkage across every sequence.
4. RFC 8785 canonical content hash recalculation for matched events.
5. Length-prefixed domain-separated SHA-256 record hash recalculation for all records (events + witnesses).
6. Chain head alignment with the bundle's declared chainHead checkpoint.
7. Conformance of all matched events to the requested filter criteria.

Zero external dependencies required (Python 3.9+ standard library only).
"""

import sys
import json
import hashlib
import struct

GENESIS_HASH = "0" * 64
DOMAIN_SEPARATOR = "AUDIT_RECORD_V1"


def length_prefixed(data: bytes) -> bytes:
    """Prepends a 4-byte big-endian unsigned length prefix to data."""
    return struct.pack(">I", len(data)) + data


def compute_record_hash(sequence_no: int, previous_hash: str, content_hash: str) -> str:
    """Computes SHA-256 record hash with length-prefixed domain separation."""
    h = hashlib.sha256()
    h.update(length_prefixed(DOMAIN_SEPARATOR.encode("utf-8")))
    h.update(length_prefixed(str(sequence_no).encode("utf-8")))
    h.update(length_prefixed(previous_hash.encode("utf-8")))
    h.update(length_prefixed(content_hash.encode("utf-8")))
    return h.hexdigest().lower()


def canonicalize_json(data) -> str:
    """RFC 8785 JSON Canonicalization Scheme (JCS) serialization."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def compute_content_hash(event: dict) -> str:
    """Constructs canonical event object and computes SHA-256 content hash."""
    canonical_obj = {
        "actorId": event.get("actorId"),
        "canonicalizationVersion": event.get("canonicalizationVersion", "JCS-1"),
        "eventId": event.get("eventId"),
        "eventType": event.get("eventType"),
        "payload": event.get("payload"),
        "recordedAt": event.get("recordedAt"),
        "resourceId": event.get("resourceId"),
        "resourceType": event.get("resourceType"),
        "sourceTimestamp": event.get("sourceTimestamp")  # None serializes as null
    }
    canonical_json = canonicalize_json(canonical_obj)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().lower()


def verify_bundle(bundle_data: dict) -> dict:
    """
    Verifies an export bundle dictionary.
    Returns a dict with verification details or raises ValueError on corruption.
    """
    chain_head = bundle_data.get("chainHead")
    if not chain_head:
        raise ValueError("CORRUPTED: Missing chainHead in bundle")

    head_seq = chain_head.get("sequenceNo")
    head_hash = chain_head.get("recordHash")

    if head_seq is None or head_hash is None or not isinstance(head_seq, int) or head_seq < 0:
        raise ValueError(f"CORRUPTED: Invalid chainHead structure or sequence number: {head_seq}")

    events = bundle_data.get("events")
    witnesses = bundle_data.get("witnesses")

    if events is None or not isinstance(events, list):
        raise ValueError("CORRUPTED: Bundle events list is null or invalid")
    if witnesses is None or not isinstance(witnesses, list):
        raise ValueError("CORRUPTED: Bundle witnesses list is null or invalid")

    if head_seq == 0:
        if head_hash != GENESIS_HASH:
            raise ValueError(f"CORRUPTED: Empty chain head hash must be genesis hash, got {head_hash}")
        if events or witnesses:
            raise ValueError("CORRUPTED: Empty chain must have 0 events and 0 witnesses")
        return {
            "status": "INTACT",
            "recordsVerified": 0,
            "matchedEvents": 0,
            "maskedEvents": 0,
            "headSequenceNo": 0,
            "headRecordHash": head_hash
        }

    # Index records by sequence number
    event_map = {}
    witness_map = {}

    for ev in events:
        if ev is None or not isinstance(ev, dict):
            raise ValueError("CORRUPTED: Event record is null or invalid")
        seq = ev.get("sequenceNo")
        if seq is None or not isinstance(seq, int) or seq < 1 or seq > head_seq:
            raise ValueError(f"CORRUPTED: Event sequence number {seq} is outside valid range [1, {head_seq}]")
        if seq in event_map:
            raise ValueError(f"CORRUPTED: Duplicate event sequence number: {seq}")
        event_map[seq] = ev

    for wt in witnesses:
        if wt is None or not isinstance(wt, dict):
            raise ValueError("CORRUPTED: Witness record is null or invalid")
        seq = wt.get("sequenceNo")
        if seq is None or not isinstance(seq, int) or seq < 1 or seq > head_seq:
            raise ValueError(f"CORRUPTED: Witness sequence number {seq} is outside valid range [1, {head_seq}]")
        if seq in witness_map:
            raise ValueError(f"CORRUPTED: Duplicate witness sequence number: {seq}")
        if seq in event_map:
            raise ValueError(f"CORRUPTED: Sequence number appears in both events and witnesses: {seq}")
        witness_map[seq] = wt

    # Verify filter criteria compliance on matched events
    filter_info = bundle_data.get("filter", {})
    filter_type = filter_info.get("filterType")
    filter_value = filter_info.get("filterValue")

    for seq, ev in event_map.items():
        if filter_type == "ACTOR_ID" and ev.get("actorId") != filter_value:
            raise ValueError(
                f"CORRUPTED: Event at seq {seq} actorId '{ev.get('actorId')}' does not match filter '{filter_value}'"
            )
        if filter_type == "RESOURCE_ID" and ev.get("resourceId") != filter_value:
            raise ValueError(
                f"CORRUPTED: Event at seq {seq} resourceId '{ev.get('resourceId')}' does not match filter '{filter_value}'"
            )

    # Contiguity & Cryptographic Linkage Check from sequence 1 to head_seq
    prev_hash = GENESIS_HASH
    matched_verified = 0
    masked_count = 0

    for seq in range(1, head_seq + 1):
        if seq in event_map:
            rec = event_map[seq]
            stored_prev = rec.get("previousHash")
            stored_content = rec.get("contentHash")
            stored_record = rec.get("recordHash")

            if rec.get("redactionType") == "MASKED":
                # Legacy masked event: plaintext was omitted in projection, so payload cannot match ingestion content hash.
                # Chain linkage and record-hash commitments are verified using stored contentHash.
                masked_count += 1
            else:
                # Full content verification: unredacted events and crypto-shredded envelopes
                calc_content = compute_content_hash(rec)
                if calc_content != stored_content.lower():
                    raise ValueError(
                        f"CORRUPTED: Content hash mismatch at seq {seq}. Stored={stored_content}, Calculated={calc_content}"
                    )
                matched_verified += 1
        elif seq in witness_map:
            rec = witness_map[seq]
            stored_prev = rec.get("previousHash")
            stored_content = rec.get("contentHash")
            stored_record = rec.get("recordHash")
        else:
            raise ValueError(f"CORRUPTED: Sequence gap detected: sequence {seq} is missing from bundle")

        # Previous hash linkage check
        if stored_prev.lower() != prev_hash.lower():
            raise ValueError(
                f"CORRUPTED: Previous hash mismatch at seq {seq}. Expected={prev_hash}, Actual={stored_prev}"
            )

        # Record hash recalculation check
        calc_record = compute_record_hash(seq, stored_prev, stored_content)
        if calc_record != stored_record.lower():
            raise ValueError(
                f"CORRUPTED: Record hash mismatch at seq {seq}. Stored={stored_record}, Calculated={calc_record}"
            )

        prev_hash = stored_record

    if len(event_map) + len(witness_map) != head_seq:
        raise ValueError(
            f"CORRUPTED: Total records in bundle ({len(event_map) + len(witness_map)}) does not match chain head sequence ({head_seq})"
        )

    # Final chain head alignment
    if prev_hash.lower() != head_hash.lower():
        raise ValueError(
            f"CORRUPTED: Chain head record hash mismatch. Head={head_hash}, TraversalTail={prev_hash}"
        )

    status = "PARTIALLY_VERIFIED_REDACTED" if masked_count > 0 else "INTACT"

    return {
        "status": status,
        "recordsVerified": head_seq,
        "matchedEvents": matched_verified,
        "maskedEvents": masked_count,
        "headSequenceNo": head_seq,
        "headRecordHash": head_hash
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/verify_export.py <export_bundle.json>", file=sys.stderr)
        sys.exit(2)

    bundle_path = sys.argv[1]
    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to read export bundle JSON: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = verify_bundle(bundle_data)
        print("=" * 60)
        print("EXPORT BUNDLE INDEPENDENT VERIFICATION RESULT")
        print("=" * 60)
        print(f"Status:               {result['status']}")
        print(f"Total Records Linked: {result['recordsVerified']}")
        print(f"Matched Events:       {result['matchedEvents']}")
        print(f"Masked Events:        {result['maskedEvents']}")
        print(f"Head Sequence No:     {result['headSequenceNo']}")
        print(f"Head Record Hash:     {result['headRecordHash']}")
        print("=" * 60)
        if result['status'] == "INTACT":
            print("All records and payloads verified intact against unbroken genesis-to-head hash chain.")
        else:
            print("Hash chain linkage verified intact. Matched payloads with legacy redaction (MASKED) are unverifiable against stored content hashes because original plaintext was omitted.")
        sys.exit(0)
    except ValueError as ve:
        print(f"VERIFICATION FAILED: {ve}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
