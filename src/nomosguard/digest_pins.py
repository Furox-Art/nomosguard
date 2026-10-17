"""Digest pins: one parser for `sha256:<hex>` and `@manifest` references.

The policy loader and the ledger paths both accept a pin from the command
line. Before this module, only the policy CLI could read a manifest, so a
ledger pin was unusable from the CLI even though `EvidenceLedger.load`
has taken `expected_digest` all along — the pin existed in the library
and could not be reached from the tool. One parser, used by every entry
point, keeps the two pins (policy bytes, ledger bytes) the same shape.

Manifest format: one `sha256:<hex>  <filename>` per line (comments with
`#` allowed) — the file an operator commits next to the artifact and
diffs in review, so the digests travel with the corpus instead of living
in code. `@file` selects the manifest's only entry; `@file:name` selects
one by filename when the manifest holds several.
"""

from __future__ import annotations

import re
from pathlib import Path


class DigestPinError(ValueError):
    """Raised when a digest pin (or its manifest) cannot be read."""


def resolve_digest_pin(pin: str | None, *, noun: str = "policy") -> str | None:
    """Resolve a pin: `sha256:<hex>` passes through, `@<manifest>` is read.

    `noun` names the artifact in error messages ("policy", "ledger").
    Callers wrap `DigestPinError` in their own domain error type.
    """
    if pin is None:
        return None
    if not pin.startswith("@"):
        return pin
    manifest_ref = pin[1:]
    name: str | None = None
    # A ":" may also be a Windows drive letter (C:\...), so the split is
    # on the LAST colon, and only counts when what precedes it is a file.
    if ":" in manifest_ref:
        head, _, tail = manifest_ref.rpartition(":")
        if Path(head).is_file():
            manifest_ref, name = head, tail
    manifest = Path(manifest_ref)
    entries: dict[str, str] = {}
    for lineno, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.partition("#")[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) not in (1, 2):
            raise DigestPinError(f"{noun} digest manifest {manifest}:{lineno}: invalid row")
        digest = parts[0]
        if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest) is None:
            raise DigestPinError(f"{noun} digest manifest {manifest}:{lineno}: invalid SHA-256 pin")
        entry_name = parts[1] if len(parts) > 1 else ""
        if entry_name in entries:
            raise DigestPinError(
                f"{noun} digest manifest {manifest}:{lineno}: duplicate entry {entry_name!r}"
            )
        entries[entry_name] = digest
    if not entries:
        raise DigestPinError(f"{noun} digest manifest is empty: {manifest}")
    if name is not None:
        if name not in entries:
            raise DigestPinError(
                f"{noun} digest manifest {manifest} has no entry for {name!r} "
                f"(has {sorted(entries)})"
            )
        return entries[name]
    if len(entries) > 1:
        raise DigestPinError(
            f"{noun} digest manifest {manifest} holds {len(entries)} entries; "
            f"name one with @{manifest}:<filename>"
        )
    return next(iter(entries.values()))
