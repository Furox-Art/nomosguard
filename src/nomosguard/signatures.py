"""Signature matching: Sigma-style, deterministic, model-free.

This is the THIRD evidence source in NomosGuard, and the only one that
needs no language model at all:

    source 1  an LLM reads telemetry and writes evidence-citing claims
    source 2  deterministic extractors parse structured records
    source 3  THIS — a signature matcher over raw log lines

A signature match is a fact about a line, not a judgement about a host:
the same log line either matches the signature or it does not, on every
run, in every process, forever. There is no score to tune and no model
to disagree with.

The philosophy: the existing system is INFERENCE over evidence. Most of
the cost and most of the uncertainty in a real pipeline sits *upstream*
of inference — in deciding what a pile of raw lines means. Signatures
are the cheap, auditable way to produce the base evidence ("this line is
a failed auth", "this line is an encoded PowerShell command") that the
inference layer then reasons over. A reviewer can read the regex and
decide whether to trust it.

THE FIELD-SCOPING APPROXIMATION (documented honestly, per the schema
contract)
--------------------------------------------------------------
Real Sigma scopes a value match to a *field*: ``EventID: 4625`` matches
4625 in the EventID field and ignores it elsewhere in the line. This
module deliberately does NOT do that, and you should know what you are
giving up:

  - the log lines here are semi-structured free text ("auth: src=1.2.3.4
    failed password"), with no declared field set and no way to know a
    priori which fields a given logsource even has;
  - so a (field, value) pair matches when BOTH regexes appear somewhere
    in the line, rather than when the value appears within the field's
    value.

That is strictly WEAKER than field scoping: it can fire on a line where
the two patterns are incidentally co-present (say, "src=… failed" and a
user-agent string that happens to contain "failed"). Two consequences
you must keep in mind when authoring signatures:

  1. choose field and value patterns that are specific enough that
     incidental co-presence is implausible (the `filter` condition
     exists for the residual cases);
  2. a match is a HINT that feeds evidence, never a conclusion. It
     becomes a claim, the claim becomes facts, and the rule engine and
     policy gate decide what it means — the same discipline as every
     other claim kind in this project.

What this module guarantees, exactly:

  1. Determinism: same line + same signature -> same result, always.
     Matching is a pure function of (line, signature) over ``re``.
  2. No fuzziness: no scoring, no thresholds beyond the regex, no
     ordering dependence, no locale, no clock, no randomness.
  3. Stable output: ``match_all`` returns matches in (signature order,
     then line order), so results serialize and diff byte-for-byte.
  4. Honest failures: a malformed regex raises ``SignatureError`` at
     compile time rather than silently never matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# -- severity / status vocabulary -------------------------------------------

#: Signature severity, Sigma's `level`. Ordered by severity so that
#: ``LEVEL_ORDER`` can be used for deterministic sorting and comparison.
LEVELS: tuple[str, ...] = (
    "informational",
    "low",
    "medium",
    "high",
    "critical",
)

#: A signature is either a curated production rule or an experimental one.
STATUSES: tuple[str, ...] = ("stable", "experimental")

# Index in LEVELS: higher is more severe.
LEVEL_ORDER: dict[str, int] = {lvl: i for i, lvl in enumerate(LEVELS)}


class SignatureError(ValueError):
    """Raised when a signature is malformed (bad regex, bad id, bad level)."""


@dataclass(frozen=True)
class Signature:
    """A single Sigma-inspired detection rule.

    ``detection`` uses Sigma's ``selection`` semantics: it is a
    conjunction. Every (field_pattern, value_pattern) pair must match —
    the field regex appears somewhere in the line AND the value regex
    appears somewhere in the line. A signature with an empty
    ``detection`` matches nothing: a signature that fires on every line
    is not a detection, it is noise.

    ``filter`` uses Sigma's ``filter`` semantics: a conjunction of
    exclusion conditions. If ANY (field_pattern, value_pattern) pair in
    ``filter`` matches, the signature does not fire — the line is
    explicitly ruled out. Use it to carve known-benign exceptions out
    of an otherwise useful signature instead of complicating the
    positive pattern.

    An empty ``filter`` (the default) excludes nothing.

    ``status`` and ``level`` are documentation and routing: they do not
    change whether the signature matches. ``level`` matters only to the
    policy layer, which escalates on critical signatures.
    """

    id: str  # stable id, e.g. "NG-0001"
    title: str
    status: str = "stable"  # stable | experimental
    level: str = "medium"  # informational | low | medium | high | critical
    logsource: str = ""  # free text: e.g. "auth", "firewall", "windows"
    description: str = ""
    # detection: ALL pairs must appear in the line (Sigma "selection" AND)
    detection: tuple[tuple[str, str], ...] = ()
    # filter: if any pair matches, the signature does NOT fire (Sigma "filter")
    filter: tuple[tuple[str, str], ...] = ()

    def validate(self) -> None:
        """Fail loudly on a malformed signature.

        Compiled here, at definition time, so a typo in a regex is a
        loud error at import rather than a signature that silently
        never fires in production.
        """
        if not isinstance(self.id, str) or not self.id.strip():
            raise SignatureError("signature.id must be a non-empty string")
        if self.status not in STATUSES:
            raise SignatureError(
                f"signature {self.id}: status {self.status!r} not one of {STATUSES}"
            )
        if self.level not in LEVELS:
            raise SignatureError(
                f"signature {self.id}: level {self.level!r} not one of {LEVELS}"
            )
        for field_pattern, value_pattern in self._all_patterns():
            try:
                re.compile(field_pattern)
                re.compile(value_pattern)
            except re.error as exc:
                raise SignatureError(
                    f"signature {self.id}: invalid regex {field_pattern!r}/"
                    f"{value_pattern!r}: {exc}"
                ) from exc

    def _all_patterns(self) -> tuple[tuple[str, str], ...]:
        return self.detection + self.filter

    @property
    def is_critical(self) -> bool:
        """Whether this signature is critical-level.

        Critical signatures are the ones the policy layer escalates on.
        """
        return self.level == "critical"

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable view (for reports and serialized matches)."""
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "level": self.level,
            "logsource": self.logsource,
            "description": self.description,
            "detection": [list(pair) for pair in self.detection],
            "filter": [list(pair) for pair in self.filter],
        }


@dataclass
class Match:
    """One signature firing on one log line.

    ``captured`` carries the capture groups of the signature's detection
    patterns, in signature order, when the patterns declare any. Groups
    are deliberately NOT interpreted — a caller that needs "the source
    IP" should ask the bridge for it (see ``signature_bridge``), not read
    a positional group. This class records WHAT matched; it does not
    decide what the captures MEAN.
    """

    signature_id: str
    line: str
    captured: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "line": self.line,
            "captured": list(self.captured),
        }


# -- the matcher --------------------------------------------------------------


def _pair_matches(line: str, pair: tuple[str, str]) -> bool:
    """Whether one (field_pattern, value_pattern) pair matches `line`.

    Both regexes are searched (not anchored) against the whole line.
    See the module docstring for why this is an approximation of Sigma's
    field-scoped matching.
    """
    field_pattern, value_pattern = pair
    return bool(re.search(field_pattern, line)) and bool(
        re.search(value_pattern, line)
    )


def match_signature(line: str, sig: Signature) -> bool:
    """Whether a single log line fires a single signature.

    Conjunction over ``detection``, veto over ``filter``:

        fires  <=>  every detection pair matches
                   AND no filter pair matches

    A signature with an empty ``detection`` never fires (see
    ``Signature.detection``). A signature with an empty ``filter`` has
    nothing to veto it.

    Deterministic: a pure function of (line, sig) over ``re``. No
    scoring, no thresholds, no fuzziness.
    """
    if not sig.detection:
        return False
    for pair in sig.detection:
        if not _pair_matches(line, pair):
            return False
    for pair in sig.filter:
        if _pair_matches(line, pair):
            return False
    return True


def _captures_for(line: str, sig: Signature) -> tuple[str, ...]:
    """Capture groups from the signature's detection patterns, in order.

    A pattern with no group contributes nothing; a pattern with N groups
    contributes all N. Pairs whose field pattern does not match the line
    are skipped — that can only happen on a line that failed the
    conjunction, and callers only read this for lines that fired.
    """
    captured: list[str] = []
    for field_pattern, value_pattern in sig.detection:
        for pattern in (field_pattern, value_pattern):
            m = re.search(pattern, line)
            if m is not None and m.groups():
                captured.extend(m.groups())
    return tuple(captured)


def match_all(
    lines: list[str], sigs: list[Signature]
) -> list[Match]:
    """Match every signature against every line.

    Output order is fixed by contract: signature order (the order of
    `sigs`), then line order (the order of `lines`). No sorting by
    severity, no grouping by logsource — a stable, byte-reproducible
    order is worth more than a pretty one, because results are diffed
    and replayed.

    Deterministic: the same (lines, sigs) always produce the same list.
    """
    matches: list[Match] = []
    for sig in sigs:
        for line in lines:
            if match_signature(line, sig):
                matches.append(
                    Match(
                        signature_id=sig.id,
                        line=line,
                        captured=_captures_for(line, sig),
                    )
                )
    return matches


def validate_signatures(sigs: list[Signature]) -> None:
    """Validate a signature set: individual syntax plus cross-signature rules.

    Raises ``SignatureError`` on the first problem found, in signature
    order:
    - a malformed signature (bad level/status/regex)
    - a duplicate signature id (ids are the claim-kind namespace — a
      collision would make two different detections indistinguishable in
      the ledger)
    - a signature whose ``detection`` is empty (it can never fire)

    Run this over any signature set at import or load time. It is cheap,
    and it converts a silent production no-op into a loud failure.
    """
    seen: set[str] = set()
    for sig in sigs:
        sig.validate()
        if sig.id in seen:
            raise SignatureError(f"duplicate signature id: {sig.id}")
        seen.add(sig.id)
        if not sig.detection:
            raise SignatureError(
                f"signature {sig.id}: empty detection — it can never fire"
            )
