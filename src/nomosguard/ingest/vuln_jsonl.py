"""Ingest CVE/vulnerability records from a JSONL log into an evidence ledger.

Line format (one JSON object per line):
    {"component": "...", "cve": "CVE-...", "severity": "high|medium|low"}

Every accepted line becomes a "vulnerability" claim whose evidence field
is sha256:<hex> of the raw line. Same discipline as tool-call ingestion:
fail-closed parsing, precise per-record errors, idempotent re-ingestion.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ledger import Claim, EvidenceLedger
from .toolcall_jsonl import IngestError

VALID_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}



@dataclass
class IngestResult:
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
    return "sha256:" + hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def parse_vuln_line(line: str, line_no: int) -> dict[str, Any]:
    """Parse and validate one JSONL CVE record. Raises IngestError."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise IngestError(f"line {line_no}: not valid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise IngestError(f"line {line_no}: record must be a JSON object, got {type(record).__name__}")

    component = record.get("component")
    cve = record.get("cve")
    if not isinstance(component, str) or not component.strip():
        raise IngestError(f"line {line_no}: missing or non-string 'component'")
    if not isinstance(cve, str) or not cve.strip():
        raise IngestError(f"line {line_no}: missing or non-string 'cve'")
    if not cve.upper().startswith("CVE-"):
        raise IngestError(f"line {line_no}: 'cve' must look like CVE-YYYY-NNNN, got {cve!r}")

    severity = record.get("severity", "unknown")
    if not isinstance(severity, str) or severity.lower() not in VALID_SEVERITIES:
        raise IngestError(
            f"line {line_no}: 'severity' must be one of {sorted(VALID_SEVERITIES)}, got {severity!r}"
        )

    payload: dict[str, Any] = {"component": component, "cve": cve, "severity": severity.lower()}
    description = record.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise IngestError(f"line {line_no}: 'description' must be a string when present")
        payload["description"] = description
    return payload


def ingest_vuln_jsonl(ledger: EvidenceLedger, path: str | Path) -> IngestResult:
    """Ingest a JSONL CVE log into the ledger. Fail-closed, idempotent."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"log file not found: {path}")

    result = IngestResult()
    seen_hashes = {
        entry.claim.evidence for entry in ledger.entries
        if entry.claim.kind == "vulnerability" and entry.claim.evidence.startswith("sha256:")
    }

    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            result.total_lines += 1
            try:
                payload = parse_vuln_line(line, line_no)
            except IngestError as exc:
                result.rejected.append({"line": line_no, "reason": str(exc)})
                continue
            evidence = _line_hash(line)
            if evidence in seen_hashes:
                result.duplicates += 1
                continue
            ledger.append(Claim(kind="vulnerability", payload=payload, evidence=evidence))
            seen_hashes.add(evidence)
            result.accepted += 1

    return result
