"""Deterministic request classification, secret masking, and detection.

Every decision here is a pure function of the request bytes and headers. There
is no model call, no entropy heuristic, and no random sampling:

* classes are chosen by a fixed priority over literal path/host/body markers;
* secrets are found by fixed regular expressions and only a masked form plus a
  short SHA-256 fingerprint leaves this module;
* paths, URLs and environment-variable references are bounded, sorted lists.

The payload SHA-256 is over the full request body, while string scanning is
bounded by ``MAX_SCAN_BYTES`` so a giant upload cannot turn observation into a
memory denial of service.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..constants import (
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TELEMETRY,
    TRAFFIC_CLASS_TOOL_RESULT,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    TRAFFIC_CLASS_UNKNOWN,
)

MAX_SCAN_BYTES = 1_048_576
MAX_DETECTIONS = 100
MAX_DETECTION_LENGTH = 512

_PROMPT_PATH_MARKERS = (
    "/chat/completions",
    "/v1/messages",
    "/v1/responses",
    "/v1/complete",
    "/v1/completions",
    "/generatecontent",
    "/v1/embeddings",
)
_PROMPT_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "api.deepseek.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.together.xyz",
)
_TELEMETRY_HOST_MARKERS = (
    "telemetry",
    "sentry",
    "statsig",
    "posthog",
    "segment.io",
    "datadoghq",
    "datadog",
    "newrelic",
    "amplitude",
    "mixpanel",
    "google-analytics",
    "analytics",
)
_TELEMETRY_PATH_MARKERS = (
    "/telemetry",
    "/metrics",
    "/stats",
    "/events",
    "/analytics",
    "/logs",
)
_TOOL_RESULT_MARKERS = (
    '"tool_result"',
    '"tool_use_id"',
    '"function_call_output"',
    '"tool_call_id"',
    '"role":"tool"',
    '"role": "tool"',
)
_TRANSCRIPT_MARKERS = ("transcript", "conversation_dump", "dump.jsonl")
_UPLOAD_MARKERS = ("upload", "/files", "transcript", "dump")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"(?<![\w])(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")
_POSIX_PATH_RE = re.compile(
    r"(?<![\w:])(?:/(?:home|Users|root|etc|var|tmp|opt|usr|mnt|workspace|data)/[^\s\"'<>|]+)"
)
_ENV_PATTERNS = (
    re.compile(r"\$(?:\{([A-Z][A-Z0-9_]{2,})\}|([A-Z][A-Z0-9_]{2,}))"),
    re.compile(r"%([A-Z][A-Z0-9_]{2,})%"),
    re.compile(
        r"(?:os\.environ|process\.env)(?:\[[\"']([A-Z][A-Z0-9_]+)[\"']\]|\.([A-Z][A-Z0-9_]+))"
    ),
    re.compile(r"\b(?:env|environment)\.([A-Z][A-Z0-9_]{2,})\b"),
)

# (name, expression, group, replacement). A fixed expression list is auditable;
# masked values never include the matched secret beyond a short prefix/suffix.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], int, str], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        0,
        "[REDACTED PRIVATE KEY]",
    ),
    (
        "anthropic-key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        0,
        "",
    ),
    (
        "openai-key",
        re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b"),
        0,
        "",
    ),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        0,
        "",
    ),
    (
        "aws-access-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0,
        "",
    ),
    (
        "bearer-token",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})"),
        1,
        "",
    ),
    (
        "password-assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*[\"']?([^\s\"',}]{8,})"
        ),
        1,
        "",
    ),
)

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "cookie", "x-auth-token"}
)


@dataclass(frozen=True)
class SecretHit:
    name: str
    masked: str
    fingerprint: str
    location: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "masked": self.masked,
            "fingerprint": self.fingerprint,
            "location": self.location,
        }


@dataclass(frozen=True)
class TrafficClassification:
    classification: str
    reasons: tuple[str, ...]
    secret_hits: tuple[SecretHit, ...]
    detected_paths: tuple[str, ...]
    detected_urls: tuple[str, ...]
    env_vars: tuple[str, ...]
    payload_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.classification,
            "reasons": list(self.reasons),
            "secret_hits": [hit.to_dict() for hit in self.secret_hits],
            "detected_paths": list(self.detected_paths),
            "detected_urls": list(self.detected_urls),
            "env_vars": list(self.env_vars),
            "payload_sha256": self.payload_sha256,
        }


@dataclass(frozen=True)
class TrafficRequest:
    method: str
    host: str
    port: int
    path: str
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return ""


def mask_secret(value: str) -> str:
    """Mask a matched secret, keeping only enough to correlate repetitions."""
    if not value:
        return "***"
    if len(value) < 12:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _iter_secret_hits(
    sources: Iterable[tuple[str, str]],
) -> tuple[SecretHit, ...]:
    hits: dict[tuple[str, str, str], SecretHit] = {}
    for location, text in sources:
        if not text:
            continue
        for name, pattern, group, replacement in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(group)
                masked = replacement or mask_secret(raw)
                hit = SecretHit(
                    name=name,
                    masked=masked,
                    fingerprint=_fingerprint(raw),
                    location=location,
                )
                hits.setdefault((name, hit.fingerprint, location), hit)
    return tuple(
        hits[key] for key in sorted(hits, key=lambda item: (item[0], item[2], item[1]))
    )


def _secret_sources(
    request: TrafficRequest, body_text: str
) -> list[tuple[str, str]]:
    sources = [("body", body_text), ("url", request.path)]
    for key, value in request.headers.items():
        if key.lower() in _SENSITIVE_HEADERS:
            sources.append((f"header:{key.lower()}", value))
    return sources


def _bounded_unique(values: Iterable[str]) -> tuple[str, ...]:
    unique = sorted({value[:MAX_DETECTION_LENGTH] for value in values if value})
    return tuple(unique[:MAX_DETECTIONS])


def _detect_paths(text: str) -> tuple[str, ...]:
    matches: list[str] = []
    for pattern in (_WINDOWS_PATH_RE, _POSIX_PATH_RE):
        matches.extend(match.group(0).rstrip(".,;:)]}") for match in pattern.finditer(text))
    return _bounded_unique(matches)


def _detect_urls(text: str) -> tuple[str, ...]:
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:)]}")
        try:
            parts = urlsplit(raw)
        except ValueError:
            # Malformed authorities (e.g. an unterminated IPv6 literal) are
            # skipped: a scanner must not fail open on a hostile URL.
            continue
        if not parts.scheme or not parts.netloc:
            continue
        # Queries are deliberately dropped: they routinely carry credentials,
        # and the secret scan already records a masked fingerprint of those.
        urls.append(f"{parts.scheme}://{parts.netloc}{parts.path}")
    return _bounded_unique(urls)


def _detect_env_vars(text: str) -> tuple[str, ...]:
    names: list[str] = []
    for pattern in _ENV_PATTERNS:
        for match in pattern.finditer(text):
            for group in match.groups():
                if group:
                    names.append(group)
    return _bounded_unique(names)


def _path_text(request: TrafficRequest) -> str:
    try:
        parts = urlsplit(request.path)
    except ValueError:
        return request.path
    return parts.path or request.path


def classify_request(request: TrafficRequest) -> TrafficClassification:
    """Classify one request with fixed priority and literal markers."""
    body_bytes = request.body[:MAX_SCAN_BYTES]
    body_text = body_bytes.decode("utf-8", errors="replace")
    body_lower = body_text.lower()
    path_lower = _path_text(request).lower()
    host_lower = request.host.lower()

    reasons: list[str] = []
    classification = TRAFFIC_CLASS_UNKNOWN

    transcript_in_body = any(marker in body_lower for marker in _TRANSCRIPT_MARKERS)
    upload_in_path = any(marker in path_lower for marker in _UPLOAD_MARKERS)
    transcript_in_path = any(marker in path_lower for marker in _TRANSCRIPT_MARKERS)
    if (transcript_in_body and upload_in_path) or transcript_in_path:
        classification = TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        if transcript_in_body:
            reasons.append("body:transcript-marker")
        if upload_in_path:
            reasons.append("path:upload")
        if transcript_in_path:
            reasons.append("path:transcript-marker")
    elif any(marker in host_lower for marker in _TELEMETRY_HOST_MARKERS):
        classification = TRAFFIC_CLASS_TELEMETRY
        reasons.append("host:telemetry")
    elif any(marker in path_lower for marker in _TELEMETRY_PATH_MARKERS):
        classification = TRAFFIC_CLASS_TELEMETRY
        reasons.append("path:telemetry")
    elif any(marker in body_lower for marker in _TOOL_RESULT_MARKERS):
        classification = TRAFFIC_CLASS_TOOL_RESULT
        reasons.append("body:tool-result")
    elif host_lower in _PROMPT_HOSTS:
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("host:model-api")
    elif any(marker in path_lower for marker in _PROMPT_PATH_MARKERS):
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("path:model-api")
    elif (
        "json" in request.header("content-type").lower()
        and any(marker in body_lower for marker in ('"messages"', '"prompt"'))
    ):
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("body:prompt-shape")

    full_text = "\n".join([_path_text(request), body_text])
    return TrafficClassification(
        classification=classification,
        reasons=tuple(reasons),
        secret_hits=_iter_secret_hits(_secret_sources(request, body_text)),
        detected_paths=_detect_paths(full_text),
        detected_urls=_detect_urls(full_text),
        env_vars=_detect_env_vars(full_text),
        payload_sha256=hashlib.sha256(request.body).hexdigest(),
    )


def build_claim_payload(
    request: TrafficRequest,
    classification: TrafficClassification,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build the ledger payload; raw body and sensitive headers never enter it."""
    payload = {
        "method": request.method,
        "host": request.host.lower(),
        "port": request.port,
        "path": _path_text(request),
        "class": classification.classification,
        "reasons": list(classification.reasons),
        "payload_sha256": classification.payload_sha256,
        "payload_bytes": len(request.body),
        "secret_hits": [hit.to_dict() for hit in classification.secret_hits],
        "detected_paths": list(classification.detected_paths),
        "detected_urls": list(classification.detected_urls),
        "env_vars": list(classification.env_vars),
        "content_type": request.header("content-type")[:MAX_DETECTION_LENGTH],
    }
    if session_id:
        payload["session_id"] = session_id
    return payload
