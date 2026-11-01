"""Outbound-traffic facts extracted from the watch ledger records.

The watch proxy is deliberately not a policy engine: it records one claim per
observed request with the deterministic classification already computed. These
extractors turn those claims into the same (subject, relation, object) facts the
rest of the rule engine consumes, so a traffic decision follows the identical
fail-closed path as a tool-call decision.

Fact vocabulary:
    (host, requestClass, class)        — an observed request class
    (host, secretExposure, pattern)    — a masked secret pattern was present
    (session, requestCount, str(n))    — how many requests the session captured
    (session, trafficSilent, "true")   — captured zero requests (never success)

The extractors are pure functions of the recorded payload. In particular the
session's silence is derived from its request count, not trusted from a
self-reported flag: a session that captured nothing is silent even if a broken
writer forgot to say so.
"""

from __future__ import annotations

from typing import Any

from .constants import (
    CLAIM_KIND_TRAFFIC_REQUEST,
    CLAIM_KIND_TRAFFIC_SESSION,
    TRAFFIC_CLASSES,
)
from .rules import ClaimValueError, Fact, _string_field, register_extractor

_HEX_SHA256 = frozenset("0123456789abcdef")


def _string_list(payload: dict[str, Any], field: str, kind: str) -> list[str]:
    value = payload.get(field, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ClaimValueError(f"{kind}: field {field!r} must be a list of strings")
    return value


def _sha256_field(payload: dict[str, Any], field: str, kind: str) -> str:
    value = _string_field(payload, field, kind)
    if value and (len(value) != 64 or not set(value) <= _HEX_SHA256):
        raise ClaimValueError(
            f"{kind}: field {field!r} must be a lowercase SHA-256 hex digest, got {value!r}"
        )
    return value


def _int_field(payload: dict[str, Any], field: str, kind: str) -> int | None:
    value = payload.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ClaimValueError(
            f"{kind}: field {field!r} must be a non-negative integer, got {value!r}"
        )
    return int(value)


@register_extractor(CLAIM_KIND_TRAFFIC_REQUEST)
def _extract_traffic_request(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from one captured outbound request.

    Payload convention:
      {"host": str, "class": str, "method": str, "path": str,
       "payload_sha256": str, "secret_hits": [{"name": str, "masked": str}]}

    A class the vocabulary does not know is refused (not coerced to
    ``unknown``): silently relabelling a captured request would hide exactly
    the traffic the watch exists to expose.
    """
    host = _string_field(payload, "host", CLAIM_KIND_TRAFFIC_REQUEST)
    classification = _string_field(payload, "class", CLAIM_KIND_TRAFFIC_REQUEST)
    if not classification:
        raise ClaimValueError(
            f"{CLAIM_KIND_TRAFFIC_REQUEST}: field 'class' is required"
        )
    if classification not in TRAFFIC_CLASSES:
        raise ClaimValueError(
            f"{CLAIM_KIND_TRAFFIC_REQUEST}: unknown traffic class "
            f"{classification!r}; expected one of {list(TRAFFIC_CLASSES)}"
        )
    _string_field(payload, "method", CLAIM_KIND_TRAFFIC_REQUEST)
    _string_field(payload, "path", CLAIM_KIND_TRAFFIC_REQUEST)
    _sha256_field(payload, "payload_sha256", CLAIM_KIND_TRAFFIC_REQUEST)
    for field in ("detected_paths", "detected_urls", "env_vars"):
        _string_list(payload, field, CLAIM_KIND_TRAFFIC_REQUEST)

    facts: list[Fact] = []
    if host:
        facts.append(
            Fact(host, "requestClass", classification, (CLAIM_KIND_TRAFFIC_REQUEST,))
        )
        hits = payload.get("secret_hits", [])
        if hits is None:
            hits = []
        if not isinstance(hits, list):
            raise ClaimValueError(
                f"{CLAIM_KIND_TRAFFIC_REQUEST}: field 'secret_hits' must be a list"
            )
        seen: set[str] = set()
        for hit in hits:
            if not isinstance(hit, dict):
                raise ClaimValueError(
                    f"{CLAIM_KIND_TRAFFIC_REQUEST}: each secret hit must be an object"
                )
            name = hit.get("name")
            masked = hit.get("masked")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(masked, str)
                or not masked
            ):
                raise ClaimValueError(
                    f"{CLAIM_KIND_TRAFFIC_REQUEST}: secret hits require "
                    "non-empty 'name' and 'masked' strings"
                )
            if name not in seen:
                seen.add(name)
                facts.append(
                    Fact(host, "secretExposure", name, (CLAIM_KIND_TRAFFIC_REQUEST,))
                )
    return facts


@register_extractor(CLAIM_KIND_TRAFFIC_SESSION)
def _extract_traffic_session(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract session facts, deriving silence from the captured count.

    Payload convention: {"session_id": str, "requests": int}
    """
    session = _string_field(payload, "session_id", CLAIM_KIND_TRAFFIC_SESSION)
    requests = _int_field(payload, "requests", CLAIM_KIND_TRAFFIC_SESSION)
    if not session or requests is None:
        return []
    facts = [
        Fact(session, "requestCount", str(requests), (CLAIM_KIND_TRAFFIC_SESSION,)),
    ]
    if requests == 0:
        facts.append(
            Fact(session, "trafficSilent", "true", (CLAIM_KIND_TRAFFIC_SESSION,))
        )
    return facts
