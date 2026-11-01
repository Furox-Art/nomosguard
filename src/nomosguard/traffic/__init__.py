"""Deterministic outbound-traffic observation for nomosguard.

Nothing in this package asks a model what a request means. The classifier is a
fixed sequence of string and structure tests; the proxy records its result as an
ordinary ledger claim; the existing rule engine and policy gate decide.
"""

from .. import facts_traffic as _facts_traffic  # noqa: F401  (registers the extractors)
from .classify import (
    SecretHit,
    TrafficClassification,
    TrafficRequest,
    build_claim_payload,
    classify_request,
)

__all__ = [
    "SecretHit",
    "TrafficClassification",
    "TrafficRequest",
    "build_claim_payload",
    "classify_request",
]
