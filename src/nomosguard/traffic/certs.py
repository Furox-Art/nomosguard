"""Local CA and leaf certificates for the loopback HTTPS proxy.

Certificate *generation* is delegated to the system ``openssl`` executable. The
package itself stays free of Python dependencies; hosts that do not ship
openssl get a precise error instead of a silently weaker TLS setup. Keys are
written with owner-only permissions, and every generated certificate is
verified against its CA before the proxy is allowed to start.

Trust-store installation is a separate, explicit act. These helpers build argv
lists (never shell strings) and accept a runner, so the platform branches are
unit-testable without touching the host's trust store.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

CA_CN = "NomosGuard Watch Local CA"
CA_DAYS = 3650
LEAF_DAYS = 825
_HOST_RE = re.compile(r"^[A-Za-z0-9.:-]+$")

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class CertificateError(RuntimeError):
    """Certificate or trust-store operation could not be completed."""


@dataclass(frozen=True)
class IssuedCertificate:
    host: str
    cert_path: Path
    key_path: Path


def _default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _detail(completed: subprocess.CompletedProcess[str]) -> str:
    text = (completed.stderr or completed.stdout or "").strip()
    return text.splitlines()[-1] if text else f"exit {completed.returncode}"


def _openssl() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise CertificateError(
            "openssl executable not found; install openssl to use the traffic watch "
            "(no Python dependency is added)"
        )
    return executable


def _run(argv: Sequence[str], *, runner: Runner | None = None, what: str) -> str:
    try:
        completed = (runner or _default_runner)(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"{what}: {exc}") from exc
    if completed.returncode != 0:
        raise CertificateError(f"{what} failed: {_detail(completed)}")
    return completed.stdout or ""


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows has no POSIX mode bits; the file still lives under the
        # user's control-plane directory.
        pass


def _pem_der(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
        return ssl.PEM_cert_to_DER_cert(text)
    except (OSError, ValueError) as exc:
        raise CertificateError(f"cannot read certificate {path}: {exc}") from exc


def certificate_fingerprint(cert_path: str | Path, algorithm: str = "sha256") -> str:
    """Uppercase hex fingerprint of a PEM certificate (no separators)."""
    der = _pem_der(Path(cert_path))
    digest = hashlib.new(algorithm, der)
    return digest.hexdigest().upper()


class CertificateAuthority:
    """A local CA plus a per-host leaf cache under one control-plane directory."""

    def __init__(
        self,
        root: str | Path,
        *,
        runner: Runner | None = None,
    ) -> None:
        self.root = Path(root)
        self.ca_dir = self.root / "ca"
        self.leaf_dir = self.root / "leafs"
        self.cert_path = self.ca_dir / "ca.crt.pem"
        self.key_path = self.ca_dir / "ca.key.pem"
        self._runner = runner
        self._lock = threading.Lock()

    def ensure(self) -> None:
        """Create the CA if absent; refuse a half-present or invalid CA."""
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        has_cert = self.cert_path.is_file()
        has_key = self.key_path.is_file()
        if has_cert != has_key:
            raise CertificateError(
                f"incomplete CA state under {self.ca_dir}: certificate and key must "
                "both exist or both be absent"
            )
        if not has_cert:
            self._generate_ca()
        self._verify(self.cert_path, what="CA self-verification")

    def _generate_ca(self) -> None:
        openssl = _openssl()
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        ca_conf = self.ca_dir / "ca.cnf"
        _write_private(
            ca_conf,
            "[req]\n"
            "prompt = no\n"
            "distinguished_name = dn\n"
            "[dn]\n"
            f"CN = {CA_CN}\n"
            "[v3_ca]\n"
            "basicConstraints = critical,CA:TRUE,pathlen:0\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always\n",
        )
        _run(
            [openssl, "genpkey", "-algorithm", "EC", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-out", str(self.key_path)],
            runner=self._runner,
            what="CA key generation",
        )
        _run(
            [openssl, "req", "-x509", "-new", "-key", str(self.key_path),
             "-days", str(CA_DAYS), "-subj", f"/CN={CA_CN}",
             "-config", str(ca_conf), "-extensions", "v3_ca",
             "-out", str(self.cert_path)],
            runner=self._runner,
            what="CA certificate generation",
        )
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass

    def _verify(self, cert_path: Path, *, what: str) -> None:
        _run(
            [_openssl(), "verify", "-CAfile", str(self.cert_path), str(cert_path)],
            runner=self._runner,
            what=what,
        )

    def fingerprint(self) -> str:
        return certificate_fingerprint(self.cert_path, "sha256")

    def thumbprint_sha1(self) -> str:
        return certificate_fingerprint(self.cert_path, "sha1")

    def issue(self, host: str) -> IssuedCertificate:
        """Issue (or reuse) a leaf certificate whose SAN is exactly ``host``."""
        host = host.strip().strip("[]")
        if not host or not _HOST_RE.fullmatch(host):
            raise CertificateError(f"refusing unsafe TLS host name: {host!r}")
        self.ensure()
        with self._lock:
            cache_key = hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:24]
            cert_path = self.leaf_dir / f"{cache_key}.crt.pem"
            key_path = self.leaf_dir / "leaf.key.pem"
            if cert_path.is_file() and key_path.is_file():
                self._verify(cert_path, what=f"leaf verification for {host}")
                return IssuedCertificate(host, cert_path, key_path)

            self.leaf_dir.mkdir(parents=True, exist_ok=True)
            if not key_path.is_file():
                _run(
                    [_openssl(), "genpkey", "-algorithm", "EC", "-pkeyopt",
                     "ec_paramgen_curve:prime256v1", "-out", str(key_path)],
                    runner=self._runner,
                    what="leaf key generation",
                )
                try:
                    os.chmod(key_path, 0o600)
                except OSError:
                    pass

            san = self._san(host)
            leaf_conf = self.leaf_dir / f"{cache_key}.cnf"
            _write_private(
                leaf_conf,
                "[req]\n"
                "prompt = no\n"
                "distinguished_name = dn\n"
                "[dn]\n"
                f"CN = {host[:64]}\n"
                "[v3_leaf]\n"
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature\n"
                "extendedKeyUsage = serverAuth\n"
                f"subjectAltName = {san}\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\n",
            )
            csr_path = self.leaf_dir / f"{cache_key}.csr.pem"
            with tempfile.TemporaryDirectory(dir=self.leaf_dir) as tmp:
                # OpenSSL needs a writable serial file; keep it out of the CA
                # directory so concurrent proxies cannot share one counter.
                serial_path = Path(tmp) / "ca.srl"
                _run(
                    [_openssl(), "req", "-new", "-key", str(key_path),
                     "-subj", f"/CN={host[:64]}", "-config", str(leaf_conf),
                     "-out", str(csr_path)],
                    runner=self._runner,
                    what=f"CSR generation for {host}",
                )
                _run(
                    [_openssl(), "x509", "-req", "-in", str(csr_path),
                     "-CA", str(self.cert_path), "-CAkey", str(self.key_path),
                     "-CAserial", str(serial_path), "-CAcreateserial",
                     "-days", str(LEAF_DAYS), "-extfile", str(leaf_conf),
                     "-extensions", "v3_leaf", "-out", str(cert_path)],
                    runner=self._runner,
                    what=f"leaf signing for {host}",
                )
            self._verify(cert_path, what=f"leaf verification for {host}")
            return IssuedCertificate(host, cert_path, key_path)

    @staticmethod
    def _san(host: str) -> str:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise CertificateError(f"refusing unsafe TLS host name: {host!r}") from None
            return f"DNS:{host}"
        return f"IP:{address.compressed}"

    def remove(self) -> None:
        """Delete CA and leaf material. Trust removal is a separate act."""
        for path in sorted(self.root.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink()
        if self.root.exists():
            try:
                self.root.rmdir()
            except OSError:
                pass


# -- trust-store installation -------------------------------------------------


def _login_keychain() -> str:
    return str(Path.home() / "Library" / "Keychains" / "login.keychain-db")


_LINUX_SYSTEM_CERT = Path("/usr/local/share/ca-certificates/nomosguard-watch.crt")
_LINUX_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


def install_trust(
    cert_path: str | Path,
    *,
    runner: Runner | None = None,
    platform: str | None = None,
    ca: CertificateAuthority | None = None,
) -> tuple[bool, str]:
    """Install the CA into the user/system trust store and verify it."""
    cert = Path(cert_path)
    platform = platform or sys.platform
    run = runner or _default_runner
    if platform.startswith("win"):
        thumb = ca.thumbprint_sha1() if ca is not None else certificate_fingerprint(cert, "sha1")
        added = run(["certutil", "-addstore", "-user", "Root", str(cert)])
        if added.returncode != 0:
            return False, f"certutil addstore failed: {_detail(added)}"
        checked = run(["certutil", "-user", "-store", "Root", thumb])
        return (
            checked.returncode == 0,
            "trusted in the current-user Root store"
            if checked.returncode == 0
            else f"certutil verification failed: {_detail(checked)}",
        )
    if platform.startswith("linux"):
        copied = run(["cp", str(cert), str(_LINUX_SYSTEM_CERT)])
        if copied.returncode != 0:
            return False, f"cannot copy CA into the system store: {_detail(copied)}"
        updated = run(["update-ca-certificates"])
        if updated.returncode != 0:
            return False, f"update-ca-certificates failed: {_detail(updated)}"
        verified = run(["openssl", "verify", "-CAfile", str(_LINUX_CA_BUNDLE), str(cert)])
        return (
            verified.returncode == 0,
            "trusted by the system CA bundle"
            if verified.returncode == 0
            else f"system bundle verification failed: {_detail(verified)}",
        )
    if platform == "darwin":
        added = run([
            "security", "add-trusted-cert", "-d", "-r", "trustRoot",
            "-k", _login_keychain(), str(cert),
        ])
        if added.returncode != 0:
            return False, f"security add-trusted-cert failed: {_detail(added)}"
        checked = run(["security", "verify-cert", "-c", str(cert), "-p", "ssl"])
        return (
            checked.returncode == 0,
            "trusted in the login keychain"
            if checked.returncode == 0
            else f"security verification failed: {_detail(checked)}",
        )
    return False, f"unsupported platform for trust installation: {platform}"


def uninstall_trust(
    cert_path: str | Path,
    *,
    runner: Runner | None = None,
    platform: str | None = None,
    ca: CertificateAuthority | None = None,
) -> tuple[bool, str]:
    """Remove the CA from the trust store and verify it is no longer trusted."""
    cert = Path(cert_path)
    platform = platform or sys.platform
    run = runner or _default_runner
    if platform.startswith("win"):
        thumb = ca.thumbprint_sha1() if ca is not None else certificate_fingerprint(cert, "sha1")
        deleted = run(["certutil", "-delstore", "-user", "Root", thumb])
        if deleted.returncode != 0:
            return False, f"certutil delstore failed: {_detail(deleted)}"
        checked = run(["certutil", "-user", "-store", "Root", thumb])
        return (
            checked.returncode != 0,
            "removed from the current-user Root store"
            if checked.returncode != 0
            else "certificate still present in the Root store",
        )
    if platform.startswith("linux"):
        removed = run(["rm", "-f", str(_LINUX_SYSTEM_CERT)])
        if removed.returncode != 0:
            return False, f"cannot remove CA from the system store: {_detail(removed)}"
        updated = run(["update-ca-certificates", "--fresh"])
        if updated.returncode != 0:
            return False, f"update-ca-certificates failed: {_detail(updated)}"
        checked = run(["openssl", "verify", "-CAfile", str(_LINUX_CA_BUNDLE), str(cert)])
        return (
            checked.returncode != 0,
            "removed from the system CA bundle"
            if checked.returncode != 0
            else "certificate still trusted by the system bundle",
        )
    if platform == "darwin":
        removed = run(["security", "remove-trusted-cert", "-d", str(cert)])
        if removed.returncode != 0:
            return False, f"security remove-trusted-cert failed: {_detail(removed)}"
        checked = run(["security", "verify-cert", "-c", str(cert), "-p", "ssl"])
        return (
            checked.returncode != 0,
            "removed from the login keychain"
            if checked.returncode != 0
            else "certificate still trusted by the login keychain",
        )
    return False, f"unsupported platform for trust removal: {platform}"
