"""CA generation, leaf issuance, removal, and trust-store argv platform matrix."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nomosguard.traffic import certs
from nomosguard.traffic.certs import (
    CA_CN,
    CertificateAuthority,
    CertificateError,
    certificate_fingerprint,
    install_trust,
    uninstall_trust,
)


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeRunner:
    def __init__(self, *, fail_on: str | None = None, returncodes: list[int] | None = None):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on
        self.returncodes = list(returncodes or [])

    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.fail_on is not None and any(self.fail_on in part for part in argv):
            return completed(1, stderr="fake failure")
        if self.returncodes:
            return completed(self.returncodes.pop(0))
        return completed(0, stdout="ok")


@pytest.fixture(scope="module")
def real_ca(tmp_path_factory) -> CertificateAuthority:
    ca = CertificateAuthority(tmp_path_factory.mktemp("real-ca"))
    ca.ensure()
    return ca


class TestHelpers:
    def test_detail_prefers_last_stderr_line(self):
        assert certs._detail(completed(1, stderr="a\nb\n")) == "b"
        assert certs._detail(completed(1, stdout="only")) == "only"
        assert certs._detail(completed(7)) == "exit 7"

    def test_run_success_returns_stdout(self):
        assert certs._run(["x"], runner=lambda argv: completed(0, stdout="yes"), what="w") == "yes"
        assert certs._run(["x"], runner=lambda argv: completed(0), what="w") == ""

    def test_run_wraps_runner_errors(self):
        def boom(argv):
            raise OSError("no exec")

        with pytest.raises(CertificateError, match="no exec"):
            certs._run(["x"], runner=boom, what="w")
        with pytest.raises(CertificateError, match="timed out"):
            certs._run(
                ["x"],
                runner=lambda argv: (_ for _ in ()).throw(subprocess.TimeoutExpired("x", 1)),
                what="w",
            )

    def test_run_reports_nonzero(self):
        with pytest.raises(CertificateError, match="w failed: boom"):
            certs._run(["x"], runner=lambda argv: completed(1, stderr="boom"), what="w")

    def test_openssl_missing_is_refused(self, monkeypatch):
        monkeypatch.setattr(certs.shutil, "which", lambda name: None)
        with pytest.raises(CertificateError, match="openssl executable not found"):
            certs._openssl()

    def test_openssl_found(self, monkeypatch):
        monkeypatch.setattr(certs.shutil, "which", lambda name: "/fake/openssl")
        assert certs._openssl() == "/fake/openssl"

    def test_write_private_ignores_chmod_failure(self, tmp_path, monkeypatch):
        def boom(path, mode):
            raise OSError("no chmod")

        monkeypatch.setattr(certs.os, "chmod", boom)
        target = tmp_path / "secret.pem"
        certs._write_private(target, "data")
        assert target.read_text(encoding="utf-8") == "data"

    def test_pem_der_errors(self, tmp_path):
        with pytest.raises(CertificateError, match="cannot read certificate"):
            certs._pem_der(tmp_path / "missing.pem")
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate", encoding="utf-8")
        with pytest.raises(CertificateError, match="cannot read certificate"):
            certs._pem_der(bad)

    def test_fingerprints(self, real_ca):
        sha256 = certificate_fingerprint(real_ca.cert_path)
        assert len(sha256) == 64 and sha256 == sha256.upper()
        sha1 = certificate_fingerprint(real_ca.cert_path, "sha1")
        assert len(sha1) == 40
        assert real_ca.fingerprint() == sha256
        assert real_ca.thumbprint_sha1() == sha1


class TestCertificateAuthority:
    def test_generated_ca_is_verifiable(self, real_ca):
        assert real_ca.cert_path.is_file()
        assert real_ca.key_path.is_file()
        assert "BEGIN CERTIFICATE" in real_ca.cert_path.read_text(encoding="utf-8")
        real_ca.ensure()  # idempotent

    def test_half_present_ca_is_refused(self, tmp_path):
        only_cert = CertificateAuthority(tmp_path / "only-cert")
        only_cert.ca_dir.mkdir(parents=True)
        only_cert.cert_path.write_text("x", encoding="utf-8")
        with pytest.raises(CertificateError, match="incomplete CA state"):
            only_cert.ensure()

        only_key = CertificateAuthority(tmp_path / "only-key")
        only_key.ca_dir.mkdir(parents=True)
        only_key.key_path.write_text("x", encoding="utf-8")
        with pytest.raises(CertificateError, match="incomplete CA state"):
            only_key.ensure()

    def test_generation_ignores_chmod_failure(self, tmp_path, monkeypatch):
        def boom(path, mode):
            raise OSError("no chmod")

        monkeypatch.setattr(certs.os, "chmod", boom)
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure()
        assert ca.cert_path.is_file()

    def test_generation_requires_openssl(self, tmp_path, monkeypatch):
        monkeypatch.setattr(certs.shutil, "which", lambda name: None)
        ca = CertificateAuthority(tmp_path / "ca")
        with pytest.raises(CertificateError, match="openssl executable not found"):
            ca.ensure()

    def test_existing_ca_with_broken_verification_is_refused(self, tmp_path):
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("cert", encoding="utf-8")
        ca.key_path.write_text("key", encoding="utf-8")
        with pytest.raises(CertificateError, match="self-verification failed"):
            ca.ensure()

    def test_issue_reuses_cached_leaf(self, real_ca):
        first = real_ca.issue("api.test")
        second = real_ca.issue("api.test")
        assert first.cert_path == second.cert_path
        assert "BEGIN CERTIFICATE" in first.cert_path.read_text(encoding="utf-8")

    def test_issue_strips_brackets_and_issues_ip(self, real_ca):
        issued = real_ca.issue("[127.0.0.1]")
        assert issued.host == "127.0.0.1"
        assert issued.cert_path.is_file()

    def test_issue_rejects_unsafe_names(self, real_ca):
        with pytest.raises(CertificateError, match="unsafe TLS host"):
            real_ca.issue("bad host")
        with pytest.raises(CertificateError, match="unsafe TLS host"):
            real_ca.issue("")
        # Passes _HOST_RE (colon is allowed) but is not a valid SAN name.
        with pytest.raises(CertificateError, match="unsafe TLS host"):
            real_ca.issue("host:name")

    def test_issue_rejects_broken_cached_leaf(self, real_ca):
        issued = real_ca.issue("cached-broken.test")
        issued.cert_path.write_text("not-a-cert", encoding="utf-8")
        with pytest.raises(CertificateError, match="leaf verification"):
            real_ca.issue("cached-broken.test")

    def test_issue_rejects_ca_that_fails_verification(self, tmp_path):
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("not-a-cert", encoding="utf-8")
        ca.key_path.write_text("not-a-key", encoding="utf-8")
        with pytest.raises(CertificateError):
            ca.issue("broken.test")

    def test_issue_failure_paths_are_wrapped(self, tmp_path):
        ca = CertificateAuthority(tmp_path / "ca", runner=FakeRunner(fail_on="x509"))
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("cert", encoding="utf-8")
        ca.key_path.write_text("key", encoding="utf-8")
        ca.leaf_dir.mkdir()
        (ca.leaf_dir / "leaf.key.pem").write_text("key", encoding="utf-8")
        with pytest.raises(CertificateError, match="leaf signing for new.test failed"):
            ca.issue("new.test")

    def test_issue_chmod_failure_is_ignored(self, tmp_path, monkeypatch):
        ca = CertificateAuthority(tmp_path / "ca", runner=FakeRunner())
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("cert", encoding="utf-8")
        ca.key_path.write_text("key", encoding="utf-8")

        def boom(path, mode):
            raise OSError("no chmod")

        monkeypatch.setattr(certs.os, "chmod", boom)
        issued = ca.issue("another.test")
        assert issued.host == "another.test"

    def test_remove_deletes_material(self, tmp_path):
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("c", encoding="utf-8")
        ca.leaf_dir.mkdir()
        (ca.leaf_dir / "x.pem").write_text("x", encoding="utf-8")
        ca.remove()
        assert not ca.root.exists()

    def test_remove_ignores_root_rmdir_failure(self, tmp_path, monkeypatch):
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ca_dir.mkdir(parents=True)
        ca.cert_path.write_text("c", encoding="utf-8")
        root = ca.root.resolve()
        original = Path.rmdir

        def rmdir(self):
            if self.resolve() == root:
                raise OSError("locked")
            return original(self)

        monkeypatch.setattr(Path, "rmdir", rmdir)
        ca.remove()
        assert ca.root.exists()
        assert not ca.cert_path.exists()


class TestInstallTrust:
    def test_windows_success(self, real_ca):
        runner = FakeRunner()
        ok, detail = install_trust(real_ca.cert_path, runner=runner, platform="win32", ca=real_ca)
        assert ok and "Root store" in detail
        assert runner.calls[0][:3] == ["certutil", "-addstore", "-user"]
        assert runner.calls[1][0] == "certutil"

    def test_windows_without_ca_object_computes_thumbprint(self, real_ca):
        runner = FakeRunner()
        ok, _ = install_trust(real_ca.cert_path, runner=runner, platform="win32")
        assert ok

    def test_windows_add_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="addstore"), platform="win32", ca=real_ca
        )
        assert not ok and "addstore failed" in detail

    def test_windows_verification_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path,
            runner=FakeRunner(returncodes=[0, 1]),
            platform="win32",
            ca=real_ca,
        )
        assert not ok and "verification failed" in detail

    def test_linux_success(self, real_ca):
        runner = FakeRunner()
        ok, detail = install_trust(real_ca.cert_path, runner=runner, platform="linux")
        assert ok and "system CA bundle" in detail
        assert runner.calls[0][0] == "cp"
        assert runner.calls[1] == ["update-ca-certificates"]

    def test_linux_copy_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="cp"), platform="linux"
        )
        assert not ok and "cannot copy CA" in detail

    def test_linux_update_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path,
            runner=FakeRunner(fail_on="update-ca-certificates"),
            platform="linux",
        )
        assert not ok and "update-ca-certificates failed" in detail

    def test_linux_verification_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="verify"), platform="linux"
        )
        assert not ok and "system bundle verification failed" in detail

    def test_darwin_success(self, real_ca):
        runner = FakeRunner()
        ok, detail = install_trust(real_ca.cert_path, runner=runner, platform="darwin")
        assert ok and "login keychain" in detail
        assert runner.calls[0][0] == "security"
        assert "add-trusted-cert" in runner.calls[0]

    def test_darwin_add_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="add-trusted-cert"), platform="darwin"
        )
        assert not ok and "add-trusted-cert failed" in detail

    def test_darwin_verification_failure(self, real_ca):
        ok, detail = install_trust(
            real_ca.cert_path,
            runner=FakeRunner(returncodes=[0, 1]),
            platform="darwin",
        )
        assert not ok and "security verification failed" in detail

    def test_unsupported_platform(self, real_ca):
        ok, detail = install_trust(real_ca.cert_path, platform="aix")
        assert not ok and "unsupported platform" in detail


class TestUninstallTrust:
    def test_windows_success(self, real_ca):
        runner = FakeRunner(returncodes=[0, 1])
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=runner, platform="win32", ca=real_ca
        )
        assert ok and "removed from the current-user Root store" in detail
        assert runner.calls[0][:3] == ["certutil", "-delstore", "-user"]

    def test_windows_without_ca_object(self, real_ca):
        ok, _ = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(returncodes=[0, 1]), platform="win32"
        )
        assert ok

    def test_windows_delete_failure(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="delstore"), platform="win32", ca=real_ca
        )
        assert not ok and "delstore failed" in detail

    def test_windows_still_present(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(returncodes=[0, 0]), platform="win32", ca=real_ca
        )
        assert not ok and "still present" in detail

    def test_linux_success(self, real_ca):
        runner = FakeRunner(returncodes=[0, 0, 1])
        ok, detail = uninstall_trust(real_ca.cert_path, runner=runner, platform="linux")
        assert ok and "removed from the system CA bundle" in detail
        assert runner.calls[1] == ["update-ca-certificates", "--fresh"]

    def test_linux_remove_failure(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="rm"), platform="linux"
        )
        assert not ok and "cannot remove CA" in detail

    def test_linux_update_failure(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path,
            runner=FakeRunner(fail_on="update-ca-certificates"),
            platform="linux",
        )
        assert not ok and "update-ca-certificates failed" in detail

    def test_linux_still_trusted(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(returncodes=[0, 0, 0]), platform="linux"
        )
        assert not ok and "still trusted" in detail

    def test_darwin_success(self, real_ca):
        runner = FakeRunner(returncodes=[0, 1])
        ok, detail = uninstall_trust(real_ca.cert_path, runner=runner, platform="darwin")
        assert ok and "removed from the login keychain" in detail
        assert runner.calls[0][0] == "security"

    def test_darwin_remove_failure(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(fail_on="remove-trusted-cert"), platform="darwin"
        )
        assert not ok and "remove-trusted-cert failed" in detail

    def test_darwin_still_trusted(self, real_ca):
        ok, detail = uninstall_trust(
            real_ca.cert_path, runner=FakeRunner(returncodes=[0, 0]), platform="darwin"
        )
        assert not ok and "still trusted" in detail

    def test_unsupported_platform(self, real_ca):
        ok, detail = uninstall_trust(real_ca.cert_path, platform="aix")
        assert not ok and "unsupported platform" in detail


def test_ca_name_constant():
    assert CA_CN == "NomosGuard Watch Local CA"
