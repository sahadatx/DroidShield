"""Short-lived, exact-target HTTPS interception for a leased disposable lab.

This is a restricted HTTP/1 proxy, never an unrestricted tunnel. It terminates
TLS using the lab CA and independently validates/pins upstream TLS through the
same transport as API testing. Application certificate pinning is left intact.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import socketserver
import ssl
import stat
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from droidshield.api_transport import TransportError, exchange
from droidshield.lab import AdbLab, LabCancelled, LabError
from droidshield.proxy_contract import PROXY_LIMITATIONS, PROXY_VERSION, ProxySummary
from droidshield.schemas import validate_target
from droidshield.services import is_excluded


def _read(path, *, private=False, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Invalid protected file")
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("Private key requires owner-only access")
        result = stream.read(limit + 1)
        if len(result) > limit:
            raise ValueError("Protected file budget exceeded")
        return result


def _ca(settings):
    try:
        if (
            os.getuid() == 0
            or os.geteuid() == 0
            or not settings.proxy_ca_cert
            or not settings.proxy_ca_key
        ):
            raise ValueError("No lab CA")
        certificate = x509.load_pem_x509_certificate(_read(settings.proxy_ca_cert))
        key = serialization.load_pem_private_key(
            _read(settings.proxy_ca_key, private=True), password=None
        )
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("RSA CA key required")

        def public(k):
            return k.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )

        if public(key.public_key()) != public(certificate.public_key()):
            raise ValueError("CA identity mismatch")
        if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("CA certificate required")
        now = datetime.now(UTC)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("CA validity required")
        return certificate, key
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound, UnsupportedAlgorithm) as exc:
        raise LabError("proxy_configuration_invalid") from exc


def proxy_configuration(settings):
    certificate, _ = _ca(settings)
    try:
        trust_hash = (
            hashlib.sha256(_read(settings.api_ca_bundle, limit=1024**2)).hexdigest()
            if settings.api_ca_bundle
            else None
        )
    except (OSError, ValueError) as exc:
        raise LabError("proxy_configuration_invalid") from exc
    return {
        "engine_version": PROXY_VERSION,
        "ca_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "upstream_ca_sha256": trust_hash,
        "allowed_networks": list(settings.api_allowed_networks),
        "observation_seconds": settings.proxy_observation_seconds,
        "max_requests": settings.proxy_max_requests,
        "request_timeout_seconds": settings.api_request_timeout_seconds,
        "max_response_bytes": settings.api_max_response_bytes,
    }


def validate_proxy_targets(targets, requested_targets, approved_targets, exclusions, package):
    try:
        if not isinstance(targets, list) or not 1 <= len(targets) <= 10:
            raise ValueError("Choose exact proxy targets")
        safe = [validate_target(item) for item in targets]
        if any(not item.startswith("https://") for item in safe) or len(set(safe)) != len(safe):
            raise ValueError("Exact unique HTTPS targets required")
        if requested_targets != [f"package:{package}", *safe]:
            raise ValueError("Proxy and assessment targets differ")
        if any(
            item not in approved_targets or any(is_excluded(item, ex) for ex in exclusions)
            for item in safe
        ):
            raise ValueError("Target is outside approved scope")
        return safe
    except (ValueError, TypeError) as exc:
        raise LabError("target_scope_invalid") from exc


def initialize_ca(directory: Path):
    """Trusted local administration; never overwrite a key or install trust."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DroidShield dedicated lab CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    for filename, value in (
        (
            "key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
        ("cert.pem", certificate.public_bytes(serialization.Encoding.PEM)),
    ):
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
        (directory / filename).chmod(0o400)


class _Server(socketserver.TCPServer):
    request_queue_size = 4
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        # HTTP bodies, TLS errors, tokens and endpoint details are never logged.
        pass


class GuardedProxy:
    def __init__(self, settings, targets, *, deadline, should_cancel):
        self.settings, self.targets = settings, tuple(targets)
        self.deadline, self.should_cancel = deadline, should_cancel
        self.certificate, self.key = _ca(settings)
        if not 1 <= len(self.targets) <= 10 or any(
            validate_target(t) != t or not t.startswith("https://") for t in self.targets
        ):
            raise LabError("target_scope_invalid")
        self.authorities = {urlsplit(t).netloc for t in self.targets}
        self.lock = threading.Lock()
        self.active = None
        self.observations = []
        self.blocked = self.tls_failures = self.attempts = 0
        self.stop = threading.Event()
        self.failure = False
        self.last_forward = 0.0
        self.temporary = tempfile.TemporaryDirectory(prefix="droidshield-proxy-")
        self.contexts = {}
        self.server = _Server(("127.0.0.1", 0), self._handler())
        self.port = self.server.server_address[1]
        self.server.timeout = 0.1
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.timer = threading.Timer(max(0.01, deadline - time.monotonic()), self._interrupt)
        self.timer.daemon = True

    def _check(self):
        if self.stop.is_set() or time.monotonic() >= self.deadline:
            raise LabError("dynamic_timeout")
        if self.should_cancel():
            raise LabCancelled()
        if self.stop.is_set() or time.monotonic() >= self.deadline:
            raise LabError("dynamic_timeout")

    def _serve(self):
        while not self.stop.is_set():
            try:
                self.server.handle_request()
            except (OSError, ValueError):
                if not self.stop.is_set():
                    self.failure = True
                    self._interrupt()
                break

    def _interrupt(self):
        self.stop.set()
        with self.lock:
            active = self.active
        if active:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def __enter__(self):
        self.thread.start()
        self.timer.start()
        return self

    def close(self):
        self._interrupt()
        self.timer.cancel()
        self.server.server_close()
        if self.thread.ident is not None:
            self.thread.join(timeout=self.settings.api_request_timeout_seconds + 2)
        self.temporary.cleanup()
        if self.thread.is_alive():
            raise LabError("proxy_cleanup_failed")

    def __exit__(self, *_args):
        self.close()

    def summary(self):
        if self.failure:
            raise LabError("proxy_failed")
        with self.lock:
            observations = list(self.observations)
            result = {
                "engine_version": PROXY_VERSION,
                "requests_forwarded": len(observations),
                "blocked_requests": self.blocked,
                "tls_failures": self.tls_failures,
                "response_bytes": sum(item["response_bytes"] for item in observations),
                "observations": observations,
                "requires_review": True,
                "limitations": PROXY_LIMITATIONS,
            }
        return ProxySummary.model_validate(result).model_dump(mode="json")

    def _context(self, authority):
        if authority in self.contexts:
            return self.contexts[authority]
        host = urlsplit("https://" + authority).hostname
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(min(now + timedelta(hours=1), self.certificate.not_valid_after_utc))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.certificate.public_key()),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )
        index = len(self.contexts)
        cert_path, key_path = (
            Path(self.temporary.name) / f"{index}.{suffix}" for suffix in ("crt", "key")
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(cert_path, key_path)
        self.contexts[authority] = context
        return context

    @staticmethod
    def _authority(value):
        if any(c in value for c in "/?#@\\"):
            raise ValueError("Invalid authority")
        return urlsplit(validate_target("https://" + value + "/")).netloc

    def _read_request(self, channel):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            self._check()
            block = channel.recv(4096)
            if not block or len(data) + len(block) > 16384:
                raise ValueError("Invalid proxy request")
            data.extend(block)
        if data.split(b"\r\n\r\n", 1)[1]:
            raise ValueError("Request body or pipelining blocked")
        lines = data.decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ValueError("Invalid protocol")
        headers = {}
        for line in lines[1:-2]:
            name, value = line.split(":", 1)
            if (
                not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name)
                or name.lower() in headers
                or any(ord(c) < 32 or ord(c) > 126 for c in value)
            ):
                raise ValueError("Invalid proxy headers")
            headers[name.lower()] = value.strip()
        if (
            "transfer-encoding" in headers
            or headers.get("content-length", "0") != "0"
            or "upgrade" in headers
            or "expect" in headers
        ):
            raise ValueError("Request bodies and upgrades are blocked")
        return method, path, headers

    def _handler(self):
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                channel = self.request
                with owner.lock:
                    owner.active = channel
                    owner.attempts += 1
                    allowed = owner.attempts <= owner.settings.proxy_max_requests + 20
                channel.settimeout(min(2, owner.settings.api_request_timeout_seconds))
                try:
                    owner._check()
                    method, authority, _ = owner._read_request(channel)
                    authority = owner._authority(authority)
                    if not allowed or method != "CONNECT" or authority not in owner.authorities:
                        raise ValueError("Proxy target blocked")
                    channel.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    channel = owner._context(authority).wrap_socket(
                        channel, server_side=True, do_handshake_on_connect=False
                    )
                    with owner.lock:
                        owner.active = channel
                    channel.do_handshake()
                    method, path, headers = owner._read_request(channel)
                    if (
                        method not in {"GET", "HEAD"}
                        or not path.startswith("/")
                        or owner._authority(headers.get("host", "")) != authority
                    ):
                        raise ValueError("Proxy method or host blocked")
                    url = validate_target("https://" + authority + path)
                    if (
                        url not in owner.targets
                        or len(owner.observations) >= owner.settings.proxy_max_requests
                    ):
                        raise ValueError("Proxy target blocked")
                    while time.monotonic() - owner.last_forward < 0.25:
                        owner._check()
                        time.sleep(0.025)
                    owner._check()
                    safe_headers = {
                        k: v
                        for k, v in headers.items()
                        if k
                        in {"accept", "accept-language", "authorization", "cookie", "user-agent"}
                    }
                    response = exchange(
                        owner.settings,
                        url,
                        method,
                        safe_headers,
                        deadline=owner.deadline,
                        should_cancel=owner.should_cancel,
                    )
                    owner._check()
                    if any(
                        name.lower() == "content-encoding" and value.lower() not in {"identity", ""}
                        for name, value in response.headers
                    ):
                        raise ValueError("Compressed upstream response blocked")
                    if response.tls_version not in {"TLSv1.2", "TLSv1.3"}:
                        raise ValueError("Unverified upstream TLS")
                    observation = {
                        "target_index": owner.targets.index(url),
                        "method": method,
                        "status_code": response.status,
                        "tls_version": response.tls_version,
                        "response_bytes": len(response.body),
                    }
                    with owner.lock:
                        owner.observations.append(observation)
                    owner.last_forward = time.monotonic()
                    if 300 <= response.status < 400:
                        raise ValueError("Redirect blocked")
                    # Transient bytes go back only to the requesting app. Evidence
                    # retains no response headers, cookies, bodies or request data.
                    body = b"" if method == "HEAD" else response.body
                    lines = [
                        f"HTTP/1.1 {response.status} Result",
                        "Connection: close",
                        "Cache-Control: no-store",
                        f"Content-Length: {len(body)}",
                    ]
                    for name, value in response.headers:
                        if (
                            name.lower() in {"content-type", "set-cookie"}
                            and len(value) <= 4096
                            and all(32 <= ord(c) <= 126 for c in value)
                        ):
                            lines.append(f"{name}: {value}")
                    channel.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
                except ssl.SSLError:
                    with owner.lock:
                        owner.tls_failures = min(10000, owner.tls_failures + 1)
                except TransportError as error:
                    with owner.lock:
                        owner.blocked = min(10000, owner.blocked + 1)
                        if "tls" in error.code:
                            owner.tls_failures = min(10000, owner.tls_failures + 1)
                except Exception:
                    with owner.lock:
                        owner.blocked = min(10000, owner.blocked + 1)
                    try:
                        channel.sendall(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    except OSError:
                        pass
                finally:
                    channel.close()
                    with owner.lock:
                        owner.active = None

        return Handler


class ProxyLab(AdbLab):
    """Permit only this app UID to reach an ADB-reversed loopback proxy."""

    scenarios = frozenset({"proxy_observe"})

    def __init__(self, settings, device, *, targets):
        super().__init__(settings, device)
        self.targets = targets
        self.proxy = None
        self.reverse = self.rules = self.global_proxy = False

    def _limitations(self, scenario):
        return list(PROXY_LIMITATIONS)

    def _observe(self, package, scenario):
        if scenario != "proxy_observe":
            raise LabError("target_scope_invalid")
        proxy_configuration(self.settings)
        if self._run("shell", "settings", "get", "global", "http_proxy") not in {"null", "", ":0"}:
            raise LabError("proxy_already_configured")
        uid_text = self._run("shell", "cmd", "package", "list", "packages", "-U", package)
        match = re.fullmatch(r"package:" + re.escape(package) + r" uid:([1-9][0-9]{4,5})", uid_text)
        if not match:
            raise LabError("package_inspection_failed")
        uid = match.group(1)
        self.proxy = GuardedProxy(
            self.settings, self.targets, deadline=self.deadline, should_cancel=self.should_cancel
        )
        self.proxy.__enter__()
        if any(
            line.split()[-2:-1] == ["tcp:8081"]
            for line in self._run("reverse", "--list").splitlines()
        ):
            raise LabError("proxy_already_configured")
        self.reverse = True
        self._run("reverse", "--no-rebind", "tcp:8081", f"tcp:{self.proxy.port}")
        self.rules = True
        for option, value, owner in (("--dport", "8081", uid), ("--sport", "8081", "0")):
            self._run(
                "shell",
                "iptables",
                "-A",
                "OUTPUT",
                "-d",
                "127.0.0.1/32",
                "-p",
                "tcp",
                option,
                value,
                "-m",
                "owner",
                "--uid-owner",
                owner,
                "-j",
                "ACCEPT",
            )
        expected = "\n".join(
            [
                "-P OUTPUT DROP",
                f"-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 8081 -m owner --uid-owner {uid} -j ACCEPT",
                "-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --sport 8081 -m owner --uid-owner 0 -j ACCEPT",
            ]
        )
        if (
            self._run("shell", "iptables", "-S", "OUTPUT") != expected
            or self._run("shell", "ip6tables", "-S", "OUTPUT") != "-P OUTPUT DROP"
        ):
            raise LabError("lab_isolation_unavailable")
        self.global_proxy = True
        self._run("shell", "settings", "put", "global", "http_proxy", "127.0.0.1:8081")
        if self._run("shell", "settings", "get", "global", "http_proxy") != "127.0.0.1:8081":
            raise LabError("lab_isolation_unavailable")
        pid, categories, count, extra = super()._observe(package, "launch_observe")
        until = min(self.deadline, time.monotonic() + self.settings.proxy_observation_seconds)
        while time.monotonic() < until:
            if self.should_cancel():
                raise LabCancelled()
            time.sleep(0.1)
        return pid, categories, count, {**extra, "traffic": self.proxy.summary()}

    def _cleanup_observer(self):
        failures = []

        def firewall():
            if self.rules:
                for binary in ("iptables", "ip6tables"):
                    self._run("shell", binary, "-P", "OUTPUT", "DROP", cleanup=True)
                    self._run("shell", binary, "-F", "OUTPUT", cleanup=True)
                    if self._run("shell", binary, "-S", "OUTPUT", cleanup=True) != "-P OUTPUT DROP":
                        raise LabError("device_cleanup_failed")

        def setting():
            if self.global_proxy:
                self._run("shell", "settings", "delete", "global", "http_proxy", cleanup=True)
                if self._run(
                    "shell", "settings", "get", "global", "http_proxy", cleanup=True
                ) not in {"null", "", ":0"}:
                    raise LabError("device_cleanup_failed")

        def reverse():
            if self.reverse:
                mappings = self._run("reverse", "--list", cleanup=True).splitlines()
                own = [
                    line.split()[-2:] for line in mappings if line.split()[-2:-1] == ["tcp:8081"]
                ]
                if own and own != [["tcp:8081", f"tcp:{self.proxy.port}"]]:
                    raise LabError("device_cleanup_failed")
                if own:
                    self._run("reverse", "--remove", "tcp:8081", cleanup=True)

        def listener():
            if self.proxy:
                self.proxy.close()

        # Device stages independently recheck the same lease at every command.
        # A failed stage cannot skip the remaining safe cleanup attempts, and a
        # missing/lost lease can never turn into an assumed ownership grant.
        for action in (firewall, setting, reverse, listener):
            try:
                action()
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise LabError("device_cleanup_failed") from failures[0]
