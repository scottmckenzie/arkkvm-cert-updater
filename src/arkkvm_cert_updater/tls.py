"""Decide whether the KVM can be trusted, before any credentials are sent.

Two modes:

* **Verified**: normal verification against the system CAs (or ``ARKKVM_CA_BUNDLE``), with the lineage's
  ``chain.pem`` intermediates offered for chain building, and hostname checking.
* **Pinned**: the server's leaf certificate must have exactly the configured SHA-256 fingerprint.
  aiohttp checks it on every new connection, after the handshake and before any request bytes are sent.
"""

from __future__ import annotations

import hmac
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certs import format_fingerprint, sha256_fingerprint


class IdentityError(Exception):
    """Raised when the KVM's certificate passes neither normal verification nor the pin."""


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def fetch_served_certificate(host: str, port: int, *, timeout: float) -> bytes:
    """Return the DER of the leaf certificate the server presents. No verification; nothing is sent."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    server_hostname = None if _is_ip_literal(host) else host
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=server_hostname) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError(f"{host}:{port} presented no certificate")
    return der


def _intermediates_only(chain_pem: bytes) -> str:
    """The certificates in ``chain_pem`` that are not self-signed, as PEM.

    Everything ``load_verify_locations`` adds goes into the trust store, and with partial chains off a
    self-signed certificate there is a trust anchor in its own right. So a root that happens to be in a
    chain file (some CAs include theirs) would be trusted even if it is not among the system CAs or in
    the configured CA bundle. Keep only what can help build a chain.
    """
    if not chain_pem.strip():
        return ""
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        for cert in x509.load_pem_x509_certificates(chain_pem)
        if cert.subject != cert.issuer
    )


def verification_context(chain_pem: bytes, ca_bundle: Path | None) -> ssl.SSLContext:
    """A strict client context: system CAs (or ``ca_bundle``) as roots, ``chain_pem`` as extra intermediates.

    Partial chains stay off, so an intermediate from ``chain.pem`` can help build a chain but never ends
    one: the chain must still reach a trusted root. (Python 3.13+ turns partial chains on by default.)
    """
    context = ssl.create_default_context(cafile=ca_bundle)
    context.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
    intermediates = _intermediates_only(chain_pem)
    if intermediates:
        context.load_verify_locations(cadata=intermediates)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def is_verified(host: str, port: int, context: ssl.SSLContext, *, timeout: float) -> bool:
    """True if the server passes ``context``'s verification for ``host``. Network failures raise ``OSError``."""
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return True
    except ssl.SSLCertVerificationError:
        return False


def served_certificate(host: str, port: int, context: ssl.SSLContext, *, timeout: float) -> tuple[bytes, bool]:
    """The DER of the leaf the server presents, and whether *that same handshake* passed ``context``.

    One verified handshake answers both questions, so the fingerprint and the verification can't come from
    two different servers (a proxy or load balancer answering separate connections differently). Only if
    verification fails is the certificate fetched without verification, and it is then never reported as
    verified. Nothing is sent either way. Network failures raise ``OSError``.
    """
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError:
        return fetch_served_certificate(host, port, timeout=timeout), False
    if not der:
        raise ssl.SSLError(f"{host}:{port} presented no certificate")
    return der, True


@dataclass(frozen=True)
class Trust:
    """How to trust the KVM. A non-``None`` ``pin`` (SHA-256 of the leaf DER) means pinned mode."""

    context: ssl.SSLContext
    pin: bytes | None

    def __post_init__(self) -> None:
        # aiohttp picks the hash by the fingerprint's length, so a 20-byte pin would silently mean SHA-1.
        if self.pin is not None and len(self.pin) != 32:
            raise ValueError("the pin must be a 32-byte SHA-256 fingerprint")


def choose_trust(host: str, port: int, *, context: ssl.SSLContext, pin: bytes | None, timeout: float) -> Trust:
    """Prefer normal verification; fall back to the pin; otherwise refuse before anything is sent."""
    if is_verified(host, port, context, timeout=timeout):
        return Trust(context, None)
    served = sha256_fingerprint(fetch_served_certificate(host, port, timeout=timeout))
    if pin is not None and hmac.compare_digest(pin, served):
        return Trust(context, pin)
    reason = "and does not match ARKKVM_TLS_FINGERPRINT" if pin is not None else "and ARKKVM_TLS_FINGERPRINT is not set"
    raise IdentityError(
        f"the certificate served by {host}:{port} fails verification {reason}. "
        f"Its SHA-256 fingerprint is {format_fingerprint(served)}. "
        "Set ARKKVM_TLS_FINGERPRINT to it only after checking in a browser that this is the KVM's certificate."
    )


def aiohttp_ssl(trust: Trust) -> ssl.SSLContext | aiohttp.Fingerprint:
    """The value for aiohttp's ``ssl=`` argument. Verified → the context; pinned → a SHA-256 fingerprint check."""
    if trust.pin is None:
        return trust.context
    return aiohttp.Fingerprint(trust.pin)
