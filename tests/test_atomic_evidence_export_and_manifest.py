"""Artifact writes and SHA manifests cannot silently redirect evidence pins."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nomosguard import evidence_export
from nomosguard.digest_pins import DigestPinError, resolve_digest_pin
from nomosguard.evidence_export import (
    ExportError,
    bundle_bytes,
    export_bundle,
    read_export_bundle,
    write_export_bundle,
)
from nomosguard.ledger import Claim, EvidenceLedger

PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64


@pytest.mark.parametrize(
    "lines",
    [
        f"{PIN_A}  evidence.json\n{PIN_B}  evidence.json\n",
        f"{PIN_A}\n{PIN_A}\n",
        f"{PIN_A} evidence.json ignored-extra\n",
        "sha256:weak evidence.json\n",
        "sha256:" + "z" * 64 + " evidence.json\n",
    ],
)
def test_ambiguous_or_malformed_sha_manifest_is_rejected(
    tmp_path: Path, lines: str
) -> None:
    manifest = tmp_path / "sha256.txt"
    manifest.write_text(lines, encoding="utf-8")
    with pytest.raises(DigestPinError, match="duplicate|invalid"):
        resolve_digest_pin("@" + str(manifest))


def test_named_sha_manifest_retains_exact_selection(tmp_path: Path) -> None:
    manifest = tmp_path / "sha256.txt"
    manifest.write_text(
        f"# reviewed digest\n{PIN_A} evidence.json # inline note\n"
        f"{PIN_B} policy.json\n",
        encoding="utf-8",
    )
    assert resolve_digest_pin(f"@{manifest}:evidence.json") == PIN_A
    assert resolve_digest_pin(f"@{manifest}:policy.json") == PIN_B
    with pytest.raises(DigestPinError, match="holds 2 entries"):
        resolve_digest_pin("@" + str(manifest))


def _bundle() -> dict:
    ledger = EvidenceLedger()
    ledger.append(Claim("audit", {"status": "PASS"}, "direct evidence"))
    return export_bundle(ledger)


def test_export_is_reproducible_and_atomically_replaces_old_contents(tmp_path: Path) -> None:
    bundle = _bundle()
    path = tmp_path / "bundle.json"
    path.write_bytes(b"previous complete export")
    write_export_bundle(path, bundle)
    assert path.read_bytes() == bundle_bytes(bundle)
    assert read_export_bundle(path) == bundle
    assert not list(tmp_path.glob(".bundle.json.*.tmp"))


def test_failed_atomic_replace_preserves_existing_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bundle.json"
    old = b"previous valid artifact was not truncated"
    path.write_bytes(old)

    def deny_replace(source: object, destination: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(evidence_export.os, "replace", deny_replace)
    with pytest.raises(ExportError, match="cannot atomically write"):
        write_export_bundle(path, _bundle())
    assert path.read_bytes() == old
    assert not list(tmp_path.glob(".bundle.json.*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="symlink privileges differ on Windows")
def test_export_destination_symlink_cannot_overwrite_unrelated_file(tmp_path: Path) -> None:
    outside = tmp_path / "original"
    outside.write_bytes(b"not the output")
    destination = tmp_path / "bundle.json"
    destination.symlink_to(outside)
    bundle = _bundle()
    write_export_bundle(destination, bundle)
    assert outside.read_bytes() == b"not the output"
    assert not destination.is_symlink()
    assert read_export_bundle(destination) == bundle
