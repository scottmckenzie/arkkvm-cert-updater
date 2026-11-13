from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import socket
import ssl
from pathlib import Path

import aiohttp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tls_server import OkHandler, serve_https

from arkkvm_cert_updater.certs import format_fingerprint, sha256_fingerprint
from arkkvm_cert_updater.tls import (
    IdentityError,
    Trust,
    aiohttp_ssl,
    choose_trust,
    fetch_served_certificate,
    is_verified,
    verification_context,
)

TIMEOUT = 5.0


def _pem_to_der(cert_pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)


def _make_cert(
    subject: str, sans: list[x509.GeneralName], issuer_name: str | None = None, issuer_key=None
) -> tuple[bytes, bytes]:
    """A leaf with exactly the given SANs; self-signed unless an issuer is given."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]) if issuer_name else name
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(dt.datetime(2060, 1, 1, tzinfo=dt.UTC))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    signer = key
    if issuer_key is not None:
        signer = issuer_key
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    cert = builder.sign(signer, hashes.SHA256())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _self_signed_localhost() -> tuple[bytes, bytes]:
    return _make_cert(
        "ArkKVM self-signed", [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    )


class RecordingHandler(OkHandler):
    """Records every request line it receives, even a malformed one."""

    received: list[bytes]

    def parse_request(self) -> bool:
        type(self).received.append(getattr(self, "raw_requestline", b""))  # set by handle_one_request
        return super().parse_request()


def _recording_handler() -> type[RecordingHandler]:
    return type("Recorder", (RecordingHandler,), {"received": []})


@pytest.fixture
def root_file(tmp_path: Path, pki) -> Path:
    path = tmp_path / "root.pem"
    path.write_bytes(pki.root_pem)
    return path


@pytest.fixture
def unrelated_ca_file(tmp_path: Path) -> Path:
    cert_pem, _ = _self_signed_localhost()
    path = tmp_path / "unrelated.pem"
    path.write_bytes(cert_pem)
    return path


@pytest.fixture
def verified_context(pki, root_file: Path) -> ssl.SSLContext:
    return verification_context(pki.intermediate_pem, root_file)


# --- fetch_served_certificate -------------------------------------------------------------------


def test_fetch_served_certificate_returns_leaf_der(pki):
    cert_pem, key_pem = pki.issue()
    with serve_https(cert_pem, key_pem) as (_, port):
        assert fetch_served_certificate("localhost", port, timeout=TIMEOUT) == _pem_to_der(cert_pem)


def test_fetch_served_certificate_ip_literal(old_cert):
    with serve_https(old_cert.cert_pem, old_cert.key_pem) as (host, port):
        assert fetch_served_certificate(host, port, timeout=TIMEOUT) == old_cert.der


def test_fetch_served_certificate_network_failure():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # bound but not listening: connection refused
        with pytest.raises(OSError):
            fetch_served_certificate("127.0.0.1", port, timeout=TIMEOUT)


# --- verification_context / is_verified ---------------------------------------------------------


def test_verification_context_is_strict(verified_context):
    assert verified_context.check_hostname is True
    assert verified_context.verify_mode == ssl.CERT_REQUIRED
    assert not verified_context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


def test_leaf_only_server_verifies_with_chain_intermediates(pki, root_file):
    cert_pem, key_pem = pki.issue()
    with serve_https(cert_pem, key_pem) as (_, port):
        assert is_verified("localhost", port, verification_context(pki.intermediate_pem, root_file), timeout=TIMEOUT)
        assert not is_verified("localhost", port, verification_context(b"", root_file), timeout=TIMEOUT)


def test_intermediate_alone_is_not_a_trust_anchor(pki, unrelated_ca_file):
    """chain.pem intermediates help build the chain, but never end it (no partial chains)."""
    cert_pem, key_pem = pki.issue()
    with serve_https(cert_pem, key_pem) as (_, port):
        context = verification_context(pki.intermediate_pem, unrelated_ca_file)
        assert not is_verified("localhost", port, context, timeout=TIMEOUT)


def test_wrong_hostname_not_verified(pki, root_file):
    cert_pem, key_pem = _make_cert(
        "other.example", [x509.DNSName("other.example")], "Test Intermediate CA", pki.intermediate_key
    )
    with serve_https(cert_pem, key_pem) as (_, port):
        # The chain itself is good (it verifies with hostname checks off), so only the name fails.
        loose = verification_context(pki.intermediate_pem, root_file)
        loose.check_hostname = False
        assert is_verified("localhost", port, loose, timeout=TIMEOUT)
        assert not is_verified(
            "localhost", port, verification_context(pki.intermediate_pem, root_file), timeout=TIMEOUT
        )


def test_is_verified_network_failure_raises(verified_context):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        with pytest.raises(OSError):
            is_verified("localhost", port, verified_context, timeout=TIMEOUT)


# --- choose_trust ---------------------------------------------------------------------------------


def test_choose_trust_verified_ignores_pin(pki, verified_context, old_cert):
    cert_pem, key_pem = pki.issue()
    unrelated_pin = sha256_fingerprint(old_cert.der)
    with serve_https(cert_pem, key_pem) as (_, port):
        trust = choose_trust("localhost", port, context=verified_context, pin=unrelated_pin, timeout=TIMEOUT)
    assert trust.pin is None
    assert trust.context is verified_context


def test_choose_trust_pinned_old_cert(old_cert, verified_context):
    pin = hashlib.sha256(old_cert.der).digest()
    with serve_https(old_cert.cert_pem, old_cert.key_pem) as (_, port):
        trust = choose_trust("localhost", port, context=verified_context, pin=pin, timeout=TIMEOUT)
    assert trust.pin == pin


@pytest.mark.parametrize("pin", [None, hashlib.sha256(b"something else").digest()], ids=["no-pin", "wrong-pin"])
def test_choose_trust_rejects(old_cert, verified_context, pin):
    served = format_fingerprint(sha256_fingerprint(old_cert.der))
    with (
        serve_https(old_cert.cert_pem, old_cert.key_pem) as (_, port),
        pytest.raises(IdentityError) as excinfo,
    ):
        choose_trust("localhost", port, context=verified_context, pin=pin, timeout=TIMEOUT)
    message = str(excinfo.value)
    assert served in message
    assert "ARKKVM_TLS_FINGERPRINT" in message
    assert "browser" in message


# --- aiohttp_ssl ----------------------------------------------------------------------------------


def test_aiohttp_ssl_verified_returns_context(verified_context):
    assert aiohttp_ssl(Trust(verified_context, None)) is verified_context


def test_aiohttp_ssl_pinned_returns_fingerprint(verified_context):
    result = aiohttp_ssl(Trust(verified_context, b"\x01" * 32))
    assert isinstance(result, aiohttp.Fingerprint)
    assert result.fingerprint == b"\x01" * 32


async def _get(url: str, ssl_arg) -> str:
    async with aiohttp.ClientSession() as session, session.get(url, ssl=ssl_arg) as response:
        return await response.text()


def test_pinned_session_accepts_matching_cert(old_cert, verified_context):
    trust = Trust(verified_context, sha256_fingerprint(old_cert.der))
    with serve_https(old_cert.cert_pem, old_cert.key_pem) as (_, port):
        assert asyncio.run(_get(f"https://localhost:{port}/", aiohttp_ssl(trust))) == "ok"


def test_pinned_session_rejects_other_cert(old_cert, verified_context):
    trust = Trust(verified_context, sha256_fingerprint(old_cert.der))
    other_pem, other_key = _self_signed_localhost()
    handler = _recording_handler()
    with (
        serve_https(other_pem, other_key, handler=handler) as (_, port),
        pytest.raises(aiohttp.ServerFingerprintMismatch),
    ):
        asyncio.run(_get(f"https://localhost:{port}/", aiohttp_ssl(trust)))
    assert handler.received == []  # rejected before any request bytes were sent


def test_verified_session_uses_our_context(pki, verified_context):
    """The test root is unknown to the system CAs, so success proves aiohttp used our context."""
    cert_pem, key_pem = pki.issue()
    with serve_https(cert_pem, key_pem) as (_, port):
        assert asyncio.run(_get(f"https://localhost:{port}/", aiohttp_ssl(Trust(verified_context, None)))) == "ok"


def test_verified_session_rejects_untrusted(old_cert, verified_context):
    handler = _recording_handler()
    with (
        serve_https(old_cert.cert_pem, old_cert.key_pem, handler=handler) as (_, port),
        pytest.raises(aiohttp.ClientConnectorCertificateError),
    ):
        asyncio.run(_get(f"https://localhost:{port}/", aiohttp_ssl(Trust(verified_context, None))))
    assert handler.received == []


@pytest.mark.parametrize("length", [0, 20, 31, 33, 64])
def test_trust_rejects_pins_that_are_not_sha256(verified_context, length):
    with pytest.raises(ValueError, match="SHA-256"):
        Trust(verified_context, b"\x01" * length)
