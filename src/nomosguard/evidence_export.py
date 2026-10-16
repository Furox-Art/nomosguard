"""Reproducible evidence export: the attestation bundle.

An audit export is only worth what a reviewer can re-check from scratch.
This module turns a ledger into a bundle that is:

- **reproducible** — the same ledger always exports byte-identical bytes,
  and the digest covers only chain-relevant content, so the same EVIDENCE
  yields the same digest even across processes and machines;
- **verifiable from scratch** — `verify_export_bundle` recomputes the
  whole chain and the digest from the bundle alone: no ledger object, no
  database, no network, no model;
- **honest about its metadata** — the wall-clock timestamps (which the
  entry hash deliberately excludes, so the chain stays reproducible) are
  isolated in one declared metadata block, in one pinned format, and
  validated on verification instead of being scattered through the
  records where nobody checks them.

Bundle layout (the pinned format):

    {
      "format": "nomosguard-evidence-export",
      "format_version": 1,
      "metadata": {
        "timestamp_format": "iso-8601-utc",
        "timestamps": {"1": "...", "2": "..."},   // seq -> timestamp
        "entry_count": 2,
        "digest_algorithm": "sha256",
        "digest_scope": "canonical-json-entries"
      },
      "entries": [
        {"seq": 1, "claim": {...}, "entry_hash": "...", "prev_hash": ""},
        ...
      ],
      "digest": "sha256:<hex of canonical JSON of entries>"
    }

The entries carry exactly what the chain authenticates — seq, claim,
entry_hash, prev_hash — and nothing that is not hashed. Anything that
deviates from the pinned format is refused with the typed `ExportError`,
the same fail-closed discipline as every other load path in this project.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .ledger import (
    Claim,
    EvidenceLedger,
    LedgerEntry,
    UnevidencedClaimError,
    _strict_loads,
)

EXPORT_FORMAT = "nomosguard-evidence-export"
EXPORT_FORMAT_VERSION = 1

#: The declared, pinned name of the timestamp format carried in the
#: metadata block. Verification checks every timestamp against it; an
#: undeclared or unpinned format is how a silent metadata drift starts.
TIMESTAMP_FORMAT = "iso-8601-utc"

#: What `TIMESTAMP_FORMAT` means mechanically: an ISO-8601 timestamp with
#: an explicit UTC designator (`Z` or `+00:00`, which is what
#: `datetime.now(timezone.utc).isoformat()` produces). No naive
#: timestamps: a string without a UTC designator is refused.
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)$"
)

DIGEST_ALGORITHM = "sha256"
#: The digest is computed over the canonical JSON of the `entries` array
#: only — never over the digest field itself, and never over the
#: (unhashed) timestamps, so the same evidence pins the same digest.
DIGEST_SCOPE = "canonical-json-entries"

_ENTRY_FIELDS = ("seq", "claim", "entry_hash", "prev_hash")


class ExportError(ValueError):
    """Raised when an export bundle is malformed or fails to verify."""


def _canonical(obj: Any) -> str:
    """Deterministic serialization: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def bundle_digest(bundle: dict[str, Any]) -> str:
    """The digest of an export bundle, computed from its entries.

    Scope is the declared `DIGEST_SCOPE`: canonical JSON of the entries
    array. The digest field itself is not part of the input, so computing
    it twice over the same entries gives the same answer.
    """
    entries = _require_entries(bundle)
    return "sha256:" + hashlib.sha256(_canonical(entries).encode("utf-8")).hexdigest()


def export_bundle(ledger: EvidenceLedger) -> dict[str, Any]:
    """Build the attestation bundle for `ledger`.

    Deterministic: same ledger -> same bundle, byte for byte. The
    per-entry timestamps are moved into the declared metadata block and
    format-checked on verification, because the entry hash deliberately
    excludes them (see `EvidenceLedger._entry_hash`).
    """
    entries: list[dict[str, Any]] = []
    timestamps: dict[str, str] = {}
    for entry in ledger.entries:
        record = entry.to_dict()
        timestamp = record.pop("timestamp")
        if not isinstance(timestamp, str) or not TIMESTAMP_RE.match(timestamp):
            raise ExportError(
                f"entry {record.get('seq')!r} carries a timestamp that is not "
                f"in the pinned {TIMESTAMP_FORMAT} format: {timestamp!r}"
            )
        record = {
            "seq": record["seq"],
            "claim": record["claim"],
            "entry_hash": record["entry_hash"],
            "prev_hash": record["prev_hash"],
        }
        timestamps[str(record["seq"])] = timestamp
        entries.append(record)

    bundle: dict[str, Any] = {
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "metadata": {
            "timestamp_format": TIMESTAMP_FORMAT,
            "timestamps": timestamps,
            "entry_count": len(entries),
            "digest_algorithm": DIGEST_ALGORITHM,
            "digest_scope": DIGEST_SCOPE,
        },
        "entries": entries,
    }
    bundle["digest"] = bundle_digest(bundle)
    return bundle


def bundle_bytes(bundle: dict[str, Any]) -> bytes:
    """The canonical bytes of a bundle (what a reviewer hashes and files).

    Two exports of the same ledger produce identical bytes — this is the
    mechanical form of the reproducibility claim.
    """
    return (_canonical(bundle) + "\n").encode("utf-8")


def write_export_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    """Write a bundle to disk in canonical form (newline='\\n', always)."""
    Path(path).write_bytes(bundle_bytes(bundle))


def read_export_bundle(path: str | Path) -> dict[str, Any]:
    """Read and structurally validate a bundle file.

    Raises `ExportError` (typed, naming the problem) on any deviation
    from the pinned format — the same refusal as the ledger load path,
    so a truncated or foreign bundle never reaches verification half-way.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ExportError(f"cannot read export bundle: {exc}") from exc
    try:
        bundle = _strict_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ExportError(f"{path}: not a valid JSON export bundle: {exc}") from exc
    _validate_structure(bundle, where=str(path))
    return bundle


def _validate_structure(bundle: Any, *, where: str) -> dict[str, Any]:
    """Validate the declared bundle shape. Returns the bundle unchanged."""
    if not isinstance(bundle, dict):
        raise ExportError(f"{where}: export bundle must be a JSON object")
    if bundle.get("format") != EXPORT_FORMAT:
        raise ExportError(
            f"{where}: missing {EXPORT_FORMAT!r} header "
            f"(got {bundle.get('format')!r})"
        )
    version = bundle.get("format_version")
    if version != EXPORT_FORMAT_VERSION:
        raise ExportError(
            f"{where}: unsupported export format version {version!r} "
            f"(expected {EXPORT_FORMAT_VERSION})"
        )
    _require_entries(bundle, where=where)

    metadata = bundle.get("metadata")
    if not isinstance(metadata, dict):
        raise ExportError(f"{where}: export bundle must carry a metadata object")
    if metadata.get("timestamp_format") != TIMESTAMP_FORMAT:
        raise ExportError(
            f"{where}: metadata.timestamp_format must be {TIMESTAMP_FORMAT!r}, "
            f"got {metadata.get('timestamp_format')!r}"
        )
    if metadata.get("digest_algorithm") != DIGEST_ALGORITHM:
        raise ExportError(
            f"{where}: metadata.digest_algorithm must be {DIGEST_ALGORITHM!r}, "
            f"got {metadata.get('digest_algorithm')!r}"
        )
    if metadata.get("digest_scope") != DIGEST_SCOPE:
        raise ExportError(
            f"{where}: metadata.digest_scope must be {DIGEST_SCOPE!r}, "
            f"got {metadata.get('digest_scope')!r}"
        )
    # A lying entry count is metadata, so the digest (over entries) cannot
    # see it: the structure check refuses it here instead of trusting it.
    if metadata.get("entry_count") != len(bundle["entries"]):
        raise ExportError(
            f"{where}: metadata.entry_count is {metadata.get('entry_count')!r} but "
            f"the bundle carries {len(bundle['entries'])} entries"
        )
    if not isinstance(metadata.get("timestamps"), dict):
        raise ExportError(f"{where}: metadata.timestamps must be an object")
    if not isinstance(bundle.get("digest"), str) or not bundle["digest"].startswith(
        "sha256:"
    ):
        raise ExportError(f"{where}: digest must look like sha256:<hex>")
    return bundle


def _require_entries(bundle: Any, *, where: str = "export bundle") -> list[Any]:
    entries = bundle.get("entries")
    if not isinstance(entries, list):
        raise ExportError(f"{where}: 'entries' must be a list")
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ExportError(f"{where}: entry {i} must be a JSON object")
        missing = [k for k in _ENTRY_FIELDS if k not in entry]
        if missing:
            raise ExportError(f"{where}: entry {i} is missing {missing}")
        if set(entry) != set(_ENTRY_FIELDS):
            raise ExportError(
                f"{where}: entry {i} carries undeclared fields "
                f"{sorted(set(entry) - set(_ENTRY_FIELDS))}"
            )
    return entries


def verify_export_bundle(bundle: Any) -> str:
    """Verify an export bundle FROM SCRATCH. Raises `ExportError` on any
    deviation; returns a one-line summary of what verified.

    The check is complete: structure, timestamp coverage and format,
    claim validity, sequence contiguity, chain links, every entry hash
    recomputed from content, and the bundle digest. Nothing is taken on
    trust from the bundle — the same discipline as `EvidenceLedger.load`.
    """
    _validate_structure(bundle, where="export bundle")
    entries = bundle["entries"]
    metadata = bundle["metadata"]
    timestamps = metadata["timestamps"]

    # -- timestamps: declared, pinned, complete ---------------------------
    expected_seqs = {str(i + 1) for i in range(len(entries))}
    if set(timestamps) != expected_seqs:
        raise ExportError(
            "metadata.timestamps does not cover the entries exactly: "
            f"missing {sorted(expected_seqs - set(timestamps))}, "
            f"unexpected {sorted(set(timestamps) - expected_seqs)}"
        )
    for seq, timestamp in timestamps.items():
        if not isinstance(timestamp, str) or not TIMESTAMP_RE.match(timestamp):
            raise ExportError(
                f"metadata.timestamps[{seq}] is not in the pinned "
                f"{TIMESTAMP_FORMAT} format: {timestamp!r}"
            )

    # -- the chain, recomputed from the bundle alone ----------------------
    prev_hash = ""
    for i, entry in enumerate(entries):
        seq = entry["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise ExportError(f"entry {i}: seq must be an integer, got {seq!r}")
        if seq != i + 1:
            raise ExportError(
                f"entry {i}: sequence broken — expected seq {i + 1}, got {seq}"
            )
        claim_data = entry["claim"]
        if not isinstance(claim_data, dict):
            raise ExportError(f"entry {seq}: claim must be an object")
        try:
            claim = Claim(
                kind=claim_data["kind"],
                payload=claim_data["payload"],
                evidence=claim_data["evidence"],
            )
            # the same claim validation the ledger append/load paths enforce
            claim.validate()
        except UnevidencedClaimError as exc:
            raise ExportError(f"entry {seq} has an invalid claim: {exc}") from exc
        except (KeyError, TypeError) as exc:
            raise ExportError(f"entry {seq} has a malformed claim: {exc}") from exc
        if entry["prev_hash"] != prev_hash:
            raise ExportError(
                f"entry {seq}: broken chain link — prev_hash does not match "
                f"entry {seq - 1}"
            )
        recomputed = EvidenceLedger._entry_hash(seq, claim, prev_hash)
        if entry["entry_hash"] != recomputed:
            raise ExportError(
                f"entry {seq}: hash mismatch — the entry does not recompute "
                "from its own content (tampered export)"
            )
        prev_hash = recomputed

    # -- the digest over the entries --------------------------------------
    recomputed_digest = bundle_digest(bundle)
    if bundle["digest"] != recomputed_digest:
        raise ExportError(
            f"digest mismatch — the bundle declares {bundle['digest']}, "
            f"its entries hash to {recomputed_digest}"
        )

    ok, detail = _verify_against_ledger(bundle)
    if not ok:
        raise ExportError(detail)
    noun = "entry" if len(entries) == 1 else "entries"
    return (
        f"export verified: {len(entries)} {noun} intact, "
        f"digest {recomputed_digest}"
    )


def _verify_against_ledger(bundle: dict[str, Any]) -> tuple[bool, str]:
    """Re-load the bundle as a ledger and run the ledger's own verify().

    The chain check above recomputes hashes directly; this re-runs the
    shipped verifier over the reconstructed ledger, so an export can
    never be accepted by a check the ledger itself would fail.
    """
    ledger = EvidenceLedger()
    timestamps = bundle["metadata"]["timestamps"]
    for entry in bundle["entries"]:
        ledger._entries.append(
            LedgerEntry(
                seq=entry["seq"],
                timestamp=timestamps[str(entry["seq"])],
                claim=Claim(
                    kind=entry["claim"]["kind"],
                    payload=entry["claim"]["payload"],
                    evidence=entry["claim"]["evidence"],
                ),
                entry_hash=entry["entry_hash"],
                prev_hash=entry["prev_hash"],
            )
        )
    return ledger.verify()


def export_ledger_file(ledger: EvidenceLedger, path: str | Path) -> dict[str, Any]:
    """Export `ledger` and write the bundle to `path`. Returns the bundle."""
    bundle = export_bundle(ledger)
    write_export_bundle(path, bundle)
    return bundle
