"""Bounded direct HTTPS probes with DNS/IP pinning and no redirects or proxies."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

_DNS_SLOTS = threading.BoundedSemaphore(4)


class TransportError(Exception):
    def __init__(self, code="request_failed"):
        self.code = code
        super().__init__(code)


class RequestCancelled(TransportError):
    def __init__(self):
        super().__init__("execution_cancelled")


@dataclass(frozen=True)
class Observation:
    status: int
    response_bytes: int
    truncated: bool
    body_digest: str
    hsts_present: bool
    content_type_present: bool
    tls_verified: bool = True


def allowed_address(address: str, networks: list[str]) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # Metadata and multicast destinations cannot be enabled by broad lab CIDRs.
    if (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or str(ip) in {"169.254.169.254", "100.100.100.200"}
    ):
        return False
    if ip.is_global:
        return True
    return any(
        ip in ipaddress.ip_network(network, strict=True)
        for network in networks
        if ip.version == ipaddress.ip_network(network, strict=True).version
    )


def resolve_addresses(
    host: str, port: int, networks: list[str], should_cancel, deadline: float
) -> list[str]:
    if not _DNS_SLOTS.acquire(blocking=False):
        raise TransportError("dns_capacity_unavailable")
    results = queue.Queue(maxsize=1)

    def resolve():
        try:
            results.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            results.put(None)
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=resolve, daemon=True, name="droidshield-api-dns").start()
    until = min(deadline, time.monotonic() + 3)
    while time.monotonic() < until:
        if should_cancel():
            raise RequestCancelled()
        try:
            entries = results.get(timeout=0.05)
            break
        except queue.Empty:
            continue
    else:
        raise TransportError("dns_timeout")
    if not entries:
        raise TransportError("dns_failed")
    addresses = list(dict.fromkeys(item[4][0] for item in entries))
    if (
        not addresses
        or len(addresses) > 32
        or not all(allowed_address(item, networks) for item in addresses)
    ):
        raise TransportError("target_network_denied")
    return addresses


@dataclass(frozen=True)
class RawResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    tls_version: str


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, context, timeout, stop):
        super().__init__(host, port, context=context, timeout=timeout)
        self.address = address
        self.stop = stop
        self.tls_version = None
        self.active_socket = None

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        self.active_socket = sock
        try:
            if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(self.address):
                raise TransportError("target_network_denied")
            if self.stop.is_set():
                raise RequestCancelled()
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            self.active_socket = self.sock
            self.tls_version = self.sock.version()
            if self.stop.is_set():
                self.sock.close()
                raise RequestCancelled()
        except Exception:
            sock.close()
            raise

    def send(self, data):
        if self.stop.is_set():
            raise RequestCancelled()
        return super().send(data)


class HTTPSProbe:
    def __init__(self, settings):
        if os.getuid() == 0 or os.geteuid() == 0:
            raise TransportError("worker_permission_denied")
        self.settings = settings
        self.context = ssl.create_default_context(cafile=getattr(settings, "api_ca_bundle", None))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(
        self,
        url: str,
        method: str,
        headers: dict,
        *,
        should_cancel,
        deadline: float,
        _raw: bool = False,
    ) -> Observation | RawResponse:
        from droidshield.schemas import validate_target

        try:
            normalized = validate_target(url)
        except ValueError as exc:
            raise TransportError("target_url_invalid") from exc
        if normalized != url:
            raise TransportError("target_url_invalid")
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.query
            or parts.fragment
            or parts.username is not None
            or method not in {"GET", "HEAD"}
        ):
            raise TransportError("target_url_invalid")
        if should_cancel():
            raise RequestCancelled()
        addresses = resolve_addresses(
            parts.hostname,
            parts.port or 443,
            self.settings.api_allowed_networks,
            should_cancel,
            deadline,
        )
        timeout = min(self.settings.api_request_timeout_seconds, deadline - time.monotonic())
        if timeout <= 0:
            raise TransportError("execution_timeout")
        stop = threading.Event()
        connection = _PinnedHTTPS(
            parts.hostname, parts.port or 443, addresses[0], self.context, timeout, stop
        )
        results = queue.Queue(maxsize=1)

        request_headers = {
            "user-agent": "DroidShield/0.4 scoped-assessment",
            "accept": "application/json",
            "accept-encoding": "identity",
            "connection": "close",
        }
        request_headers.update({key.lower(): value for key, value in headers.items()})

        def work():
            try:
                if stop.is_set():
                    raise RequestCancelled()
                connection.request(
                    method,
                    parts.path or "/",
                    headers=request_headers,
                )
                response = connection.getresponse()
                response_headers = response.getheaders()
                if sum(len(key) + len(value) + 4 for key, value in response_headers) > 65536:
                    raise TransportError("response_headers_exceeded")
                tls_version = connection.tls_version
                if tls_version not in {"TLSv1.2", "TLSv1.3"}:
                    raise TransportError("tls_verification_failed")
                chunks = []
                limit = self.settings.api_max_response_bytes
                digest = hashlib.sha256()
                size, truncated = 0, False
                while True:
                    if stop.is_set():
                        raise RequestCancelled()
                    chunk = response.read(min(4096, limit + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    if _raw:
                        chunks.append(chunk)
                    if size > limit:
                        size, truncated = limit, True
                        break
                result = Observation(
                    response.status,
                    size,
                    truncated,
                    digest.hexdigest(),
                    response.getheader("Strict-Transport-Security") is not None,
                    response.getheader("Content-Type") is not None,
                )
                if _raw:
                    if truncated:
                        raise TransportError("response_body_exceeded")
                    result = RawResponse(
                        response.status, response_headers, b"".join(chunks), tls_version
                    )
                results.put(result)
            except TransportError as exc:
                results.put(exc)
            except ssl.SSLError:
                results.put(TransportError("tls_verification_failed"))
            except (OSError, ValueError, http.client.HTTPException):
                results.put(TransportError("request_failed"))
            finally:
                connection.close()

        threading.Thread(target=work, daemon=True, name="droidshield-api-request").start()
        until = min(deadline, time.monotonic() + timeout)
        try:
            while time.monotonic() < until:
                if should_cancel():
                    raise RequestCancelled()
                try:
                    result = results.get(timeout=0.05)
                except queue.Empty:
                    continue
                if isinstance(result, TransportError):
                    raise result
                if not 100 <= result.status <= 599:
                    raise TransportError("response_invalid")
                return result
            raise TransportError("request_timeout")
        finally:
            stop.set()
            if connection.active_socket is not None:
                try:
                    connection.active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()


def exchange(settings, url, method, headers, *, deadline, should_cancel) -> RawResponse:
    """Transient TLS-verified response for the controlled lab proxy; never persisted."""
    return HTTPSProbe(settings).request(
        url, method, headers, should_cancel=should_cancel, deadline=deadline, _raw=True
    )
