"""Evidence ingestion: turn raw logs into evidence-citing claims.

The ingestion layer is where raw data becomes *evidence*. Two rules make
that transformation trustworthy:

1. Every claim cites the exact evidence fragment — the SHA-256 hash of the
   raw source line. A reviewer can recompute the hash from the original log
   and confirm the claim is not a paraphrase.
2. Malformed records are rejected loudly, one precise error per record.
   Nothing is silently dropped or coerced — a security audit trail that
   quietly skips lines is worse than no trail at all.
"""

from .toolcall_jsonl import IngestError, IngestResult, ingest_toolcall_jsonl

__all__ = ["IngestError", "IngestResult", "ingest_toolcall_jsonl"]
