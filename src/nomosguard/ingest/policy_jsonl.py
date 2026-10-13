"""Ingest policy-rule records from a JSONL log into an evidence ledger.

Line format (one JSON object per line):
    {"subject": "...", "action": "...", "resource": "...", "effect": "allow|deny"}

Every accepted line becomes a "policy_rule" claim whose evidence field is
sha256:<hex> of the raw line. Same discipline as the other adapters:
fail-closed parsing, precise per-record errors, idempotent re-ingestion.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..constants import VALID_POLICY_EFFECTS
from ..ledger import Claim, EvidenceLedger
from ..schema import RecordValidator, parse_json_record
from .toolcall_jsonl import IngestError

VALID_EFFECTS = VALID_POLICY_EFFECTS



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


def parse_policy_line(line: str, line_no: int) -> dict[str, Any]:
    """Parse and validate one JSONL policy-rule record. Raises IngestError.

    The `effect` field is a closed vocabulary: an unknown value is refused
    rather than coerced to deny (see `nomosguard.rules._extract_policy_rule`,
    which holds the same rule on the engine side). Messages follow the
    project-wide contract in `nomosguard.schema`.
    """
    where = f"line {line_no}"
    record = parse_json_record(line, where, error=IngestError)
    v = RecordValidator(record, where, error=IngestError)

    subject = v.string("subject")
    action = v.string("action")
    resource = v.string("resource")
    effect = v.enum("effect", VALID_EFFECTS, default="")

    return {
        "subject": subject,
        "action": action,
        "resource": resource,
        "effect": effect,
    }


def ingest_policy_jsonl(ledger: EvidenceLedger, path: str | Path) -> IngestResult:
    """Ingest a JSONL policy log into the ledger. Fail-closed, idempotent."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"log file not found: {path}")

    result = IngestResult()
    seen_hashes = {
        entry.claim.evidence for entry in ledger.entries
        if entry.claim.kind == "policy_rule" and entry.claim.evidence.startswith("sha256:")
    }

    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            result.total_lines += 1
            try:
                payload = parse_policy_line(line, line_no)
            except IngestError as exc:
                result.rejected.append({"line": line_no, "reason": str(exc)})
                continue
            evidence = _line_hash(line)
            if evidence in seen_hashes:
                result.duplicates += 1
                continue
            ledger.append(Claim(kind="policy_rule", payload=payload, evidence=evidence))
            seen_hashes.add(evidence)
            result.accepted += 1

    return result
