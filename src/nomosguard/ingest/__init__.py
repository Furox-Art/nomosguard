"""Evidence ingestion: turn raw logs into evidence-citing claims.

Three adapters, one discipline:
1. Every claim cites the exact evidence fragment — the SHA-256 hash of the
   raw source line. A reviewer can recompute the hash from the original log
   and confirm the claim is not a paraphrase.
2. Malformed records are rejected loudly, one precise error per record.
   Nothing is silently dropped or coerced — a security audit trail that
   quietly skips lines is worse than no trail at all.
3. Re-ingestion is idempotent (duplicate evidence hashes are detected).
"""

from .toolcall_jsonl import IngestError, IngestResult, ingest_toolcall_jsonl
from .vuln_jsonl import ingest_vuln_jsonl
from .policy_jsonl import ingest_policy_jsonl

__all__ = [
    "IngestError",
    "IngestResult",
    "ingest_toolcall_jsonl",
    "ingest_vuln_jsonl",
    "ingest_policy_jsonl",
]
