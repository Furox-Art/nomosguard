"""Ingest tool-call records from a JSONL log into an evidence ledger.

Line format (one JSON object per line):
    {"agent": "...", "tool": "...", "target": "...", "args": {...}}

Every accepted line becomes a "tool_call" claim whose `evidence` field is
`sha256:<hex> of the raw line`. The hash makes the claim independently
verifiable: recompute it from the source log and compare.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ledger import Claim, EvidenceLedger
from ..schema import RecordValidator, parse_json_record


class IngestError(ValueError):
    """Raised when a record cannot be ingested (malformed, missing fields)."""


@dataclass
class IngestResult:
    """The outcome of ingesting one file.

    `accepted` and `rejected` are per-record; `rejected` entries carry the
    1-based line number and the precise reason. Nothing is silently
    skipped — the counts always add up to the number of non-empty lines.
    """

    accepted: int = 0
    duplicates: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    total_lines: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "total_lines": self.total_lines,
        }


def _line_hash(raw_line: str) -> str:
    """Deterministic SHA-256 of a raw log line (the evidence citation)."""
    return "sha256:" + hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def parse_toolcall_line(line: str, line_no: int) -> dict[str, Any]:
    """Parse and validate one JSONL tool-call record.

    Returns the claim payload. Raises IngestError with the line number and
    the precise problem on any deviation — no coercion, no defaults
    invented for missing fields. Messages follow the project-wide contract
    in `nomosguard.schema`: `<location>: field <name> <reason>[, got <value>]`.
    """
    where = f"line {line_no}"
    record = parse_json_record(line, where, error=IngestError)
    v = RecordValidator(record, where, error=IngestError)

    agent = v.string("agent")
    tool = v.string("tool")
    target = v.string("target", required=False)
    args = v.object("args")

    payload: dict[str, Any] = {"agent": agent, "tool": tool}
    if target is not None:
        payload["target"] = target
    if args is not None:
        payload["args"] = args
    return payload


def ingest_toolcall_jsonl(
    ledger: EvidenceLedger,
    path: str | Path,
) -> IngestResult:
    """Ingest a JSONL tool-call log into the ledger.

    Fail-closed semantics:
    - blank lines are skipped (they carry no record)
    - malformed records are rejected with line number + reason
    - a record whose evidence hash already exists in the ledger is a
      duplicate: counted, not re-appended (idempotent re-ingestion)
    """
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"log file not found: {path}")

    result = IngestResult()
    seen_hashes = {
        entry.claim.evidence for entry in ledger.entries
        if entry.claim.kind == "tool_call" and entry.claim.evidence.startswith("sha256:")
    }

    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            result.total_lines += 1
            try:
                payload = parse_toolcall_line(line, line_no)
            except IngestError as exc:
                result.rejected.append({"line": line_no, "reason": str(exc)})
                continue
            evidence = _line_hash(line)
            if evidence in seen_hashes:
                result.duplicates += 1
                continue
            ledger.append(Claim(kind="tool_call", payload=payload, evidence=evidence))
            seen_hashes.add(evidence)
            result.accepted += 1

    return result
