"""Deterministic classification, secret masking, and detection bounds."""

from __future__ import annotations

import hashlib

import pytest

import nomosguard.traffic.classify as classify_module
from nomosguard.constants import (
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TELEMETRY,
    TRAFFIC_CLASS_TOOL_RESULT,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    TRAFFIC_CLASS_UNKNOWN,
)
from nomosguard.traffic import (
    SecretHit,
    TrafficClassification,
    TrafficRequest,
    build_claim_payload,
    classify_request,
)


def request(
    *,
    host: str = "example.test",
    port: int = 443,
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    method: str = "POST",
) -> TrafficRequest:
    return TrafficRequest(
        method=method,
        host=host,
        port=port,
        path=path,
        headers=headers or {},
        body=body,
    )


class TestClassificationPriority:
    def test_prompt_by_model_host(self):
        result = classify_request(request(host="api.anthropic.com", path="/v1/messages"))
        assert result.classification == TRAFFIC_CLASS_PROMPT
        assert result.reasons == ("host:model-api",)

    def test_prompt_by_model_path(self):
        result = classify_request(request(host="proxy.example", path="/v1/chat/completions"))
        assert result.classification == TRAFFIC_CLASS_PROMPT
        assert result.reasons == ("path:model-api",)

    def test_prompt_by_json_shape(self):
        result = classify_request(
            request(
                path="/api",
                headers={"Content-Type": "application/json; charset=utf-8"},
                body=b'{"messages": []}',
            )
        )
        assert result.classification == TRAFFIC_CLASS_PROMPT
        assert result.reasons == ("body:prompt-shape",)

    def test_prompt_shape_requires_json_content_type(self):
        result = classify_request(
            request(path="/api", headers={"Content-Type": "text/plain"}, body=b'{"messages": []}')
        )
        assert result.classification == TRAFFIC_CLASS_UNKNOWN

    def test_telemetry_by_host(self):
        result = classify_request(request(host="in.telemetry.vendor.test", path="/v1/ingest"))
        assert result.classification == TRAFFIC_CLASS_TELEMETRY
        assert result.reasons == ("host:telemetry",)

    def test_telemetry_by_path(self):
        result = classify_request(request(host="example.test", path="/metrics"))
        assert result.classification == TRAFFIC_CLASS_TELEMETRY
        assert result.reasons == ("path:telemetry",)

    def test_transcript_upload_body_and_upload_path(self):
        result = classify_request(
            request(path="/upload", body=b'{"kind": "transcript"}')
        )
        assert result.classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        assert result.reasons == ("body:transcript-marker", "path:upload")

    def test_transcript_upload_path_only(self):
        result = classify_request(request(path="/v1/transcript"))
        assert result.classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        assert result.reasons == ("path:upload", "path:transcript-marker")

    def test_transcript_body_without_upload_path_is_not_upload(self):
        result = classify_request(request(host="api.openai.com", path="/v1/responses", body=b"transcript"))
        assert result.classification == TRAFFIC_CLASS_PROMPT
        assert result.reasons == ("host:model-api",)

    def test_transcript_outranks_telemetry(self):
        result = classify_request(request(host="telemetry.vendor.test", path="/upload", body=b"transcript"))
        assert result.classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD

    def test_transcript_path_reason_does_not_depend_on_upload_marker(self, monkeypatch):
        monkeypatch.setattr(classify_module, "_UPLOAD_MARKERS", ("upload",))
        result = classify_request(request(path="/transcript"))
        assert result.classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        assert result.reasons == ("path:transcript-marker",)

    def test_tool_result(self):
        result = classify_request(request(path="/v1/messages", body=b'{"role":"tool"}'))
        assert result.classification == TRAFFIC_CLASS_TOOL_RESULT
        assert result.reasons == ("body:tool-result",)

    def test_unknown(self):
        result = classify_request(request(path="/health", body=b"ok"))
        assert result.classification == TRAFFIC_CLASS_UNKNOWN
        assert result.reasons == ()

    def test_query_is_not_part_of_classification_path(self):
        result = classify_request(request(path="/api?next=/metrics"))
        assert result.classification == TRAFFIC_CLASS_UNKNOWN


class TestSecretDetection:
    def test_mask_secret(self):
        assert classify_module.mask_secret("") == "***"
        assert classify_module.mask_secret("short") == "***"
        assert classify_module.mask_secret("abcdefghijkl") == "abcd…ijkl"

    def test_each_pattern_is_detected_and_masked(self):
        pem_header = "-----BEGIN RSA " + "PRIVATE KEY-----"
        body = (
            (pem_header + "\n").encode()
            + b"sk-ant-abcdefghijklmnopqrstuvwx\n"
            b"sk-proj-abcdefghijklmnopqrstuvwx\n"
            b"ghp_abcdefghijklmnopqrstuvwxyz012345\n"
            b"AKIA1234567890ABCDEF\n"
            b"Bearer abcdefghijklmnopqrstuvwxyz\n"
            b'password = "hunter2hunter2"\n'
        )
        result = classify_request(request(body=body))
        names = {hit.name for hit in result.secret_hits}
        assert names == {
            "private-key",
            "anthropic-key",
            "openai-key",
            "github-token",
            "aws-access-key",
            "bearer-token",
            "password-assignment",
        }
        private = next(hit for hit in result.secret_hits if hit.name == "private-key")
        assert private.masked == "[REDACTED PRIVATE KEY]"
        assert private.location == "body"
        assert len(private.fingerprint) == 16
        bearer = next(hit for hit in result.secret_hits if hit.name == "bearer-token")
        assert bearer.masked == "abcd…wxyz"

    def test_short_secret_is_fully_masked(self):
        result = classify_request(request(body=b"ghp_abcdefghijklmnopqrst"))  # 20 chars after prefix
        hit = next(hit for hit in result.secret_hits if hit.name == "github-token")
        assert hit.masked.startswith("ghp_") and hit.masked.endswith("qrst")

    def test_sensitive_headers_are_scanned(self):
        result = classify_request(
            request(
                headers={
                    "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
                    "X-API-Key": "sk-abcdefghijklmnopqrstuvwx",
                }
            )
        )
        locations = {hit.location for hit in result.secret_hits}
        assert "header:authorization" in locations
        assert "header:x-api-key" in locations

    def test_duplicate_secret_in_same_location_is_reported_once(self):
        body = b"ghp_abcdefghijklmnopqrstuvwxyz012345 ghp_abcdefghijklmnopqrstuvwxyz012345"
        result = classify_request(request(body=body))
        hits = [hit for hit in result.secret_hits if hit.name == "github-token"]
        assert len(hits) == 1

    def test_secret_in_url_query_is_masked_and_query_is_stripped(self):
        result = classify_request(
            request(path="/cb?token=ghp_abcdefghijklmnopqrstuvwxyz012345&x=1")
        )
        url_hits = [hit for hit in result.secret_hits if hit.location == "url"]
        assert url_hits and url_hits[0].name == "github-token"
        assert result.detected_urls == ()

    def test_empty_header_value_is_skipped(self):
        result = classify_request(request(headers={"Authorization": ""}, body=b"plain"))
        assert not [hit for hit in result.secret_hits if hit.location.startswith("header:")]


class TestDetection:
    def test_paths_urls_and_env_vars(self):
        body = (
            b"read C:\\Users\\me\\secret.txt and /home/me/.ssh/id_rsa, "
            b"see https://api.example.test/v1/data?token=abc, "
            b"use ${API_TOKEN} and %HOME% and os.environ['DB_PASS'] "
            b"and process.env.AWS_KEY and env.SECRET_NAME"
        )
        result = classify_request(request(body=body))
        assert "C:\\Users\\me\\secret.txt" in result.detected_paths
        assert "/home/me/.ssh/id_rsa" in result.detected_paths
        assert result.detected_urls == ("https://api.example.test/v1/data",)
        assert set(result.env_vars) == {
            "API_TOKEN",
            "HOME",
            "DB_PASS",
            "AWS_KEY",
            "SECRET_NAME",
        }

    def test_malformed_url_is_skipped_not_fatal(self):
        result = classify_request(request(body=b"bad http://[::1 and good https://ok.test/x"))
        assert result.detected_urls == ("https://ok.test/x",)

    def test_url_without_a_netloc_is_skipped(self):
        result = classify_request(request(body=b"http://?q=1 https://ok.test/x"))
        assert result.detected_urls == ("https://ok.test/x",)

    def test_malformed_request_path_is_used_raw(self):
        result = classify_request(request(path="http://[::1"))
        assert result.payload_sha256 == hashlib.sha256(b"").hexdigest()
        assert result.classification == TRAFFIC_CLASS_UNKNOWN

    def test_detections_are_bounded_and_truncated(self):
        urls = " ".join(
            f"https://h{index}.test/{'a' * 600}"
            for index in range(classify_module.MAX_DETECTIONS + 5)
        )
        result = classify_request(request(body=urls.encode()))
        assert len(result.detected_urls) == classify_module.MAX_DETECTIONS
        assert all(
            len(url) <= classify_module.MAX_DETECTION_LENGTH
            for url in result.detected_urls
        )

    def test_scan_is_bounded_but_hash_covers_full_body(self):
        filler = b"a" * (classify_module.MAX_SCAN_BYTES + 10)
        body = filler + b" sk-ant-abcdefghijklmnopqrstuvwx"
        result = classify_request(request(body=body))
        assert not [hit for hit in result.secret_hits if hit.name == "anthropic-key"]
        assert result.payload_sha256 == hashlib.sha256(body).hexdigest()


class TestPayload:
    def test_payload_excludes_raw_body_and_sensitive_headers(self):
        body = b'{"prompt": "hi", "key": "sk-ant-abcdefghijklmnopqrstuvwx"}'
        req = request(
            host="API.Anthropic.com",
            path="/v1/messages?token=sk-ant-abcdefghijklmnopqrstuvwx",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
            },
            body=body,
        )
        result = classify_request(req)
        payload = build_claim_payload(req, result, session_id="s-1")
        assert payload["host"] == "api.anthropic.com"
        assert payload["path"] == "/v1/messages"
        assert payload["class"] == TRAFFIC_CLASS_PROMPT
        assert payload["payload_sha256"] == hashlib.sha256(body).hexdigest()
        assert payload["payload_bytes"] == len(body)
        assert payload["session_id"] == "s-1"
        assert payload["content_type"] == "application/json"
        assert "sk-ant-abcdefghijklmnopqrstuvwx" not in repr(payload)
        assert "abcdefghijklmnopqrstuvwxyz" not in repr(payload)

    def test_payload_without_session_has_no_session_key(self):
        req = request(path="/health")
        payload = build_claim_payload(req, classify_request(req))
        assert "session_id" not in payload

    def test_content_type_is_truncated(self):
        req = request(headers={"Content-Type": "x" * 600})
        payload = build_claim_payload(req, classify_request(req))
        assert len(payload["content_type"]) == classify_module.MAX_DETECTION_LENGTH

    def test_request_header_lookup_is_case_insensitive(self):
        req = request(headers={"X-Trace": "yes"})
        assert req.header("x-trace") == "yes"
        assert req.header("missing") == ""

    def test_dataclasses_serialize(self):
        hit = SecretHit("github-token", "ghp_…1234", "abc", "body")
        assert hit.to_dict()["name"] == "github-token"
        result = TrafficClassification(
            classification=TRAFFIC_CLASS_UNKNOWN,
            reasons=(),
            secret_hits=(hit,),
            detected_paths=(),
            detected_urls=(),
            env_vars=(),
            payload_sha256="0" * 64,
        )
        rendered = result.to_dict()
        assert rendered["secret_hits"][0]["location"] == "body"


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("api.openai.com", "/anything"),
        ("API.OPENAI.COM", "/anything"),
        ("example.test", "/v1/responses"),
    ],
)
def test_prompt_hosts_accept_case_and_host_variants(host: str, path: str):
    assert classify_request(request(host=host, path=path)).classification == TRAFFIC_CLASS_PROMPT
