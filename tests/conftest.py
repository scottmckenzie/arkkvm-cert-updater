"""Shared fixtures: a throwaway test PKI (root, intermediate, leaves) and certbot-style lineages."""

from __future__ import annotations

import datetime as dt
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KEY_TYPES = ("rsa2048", "rsa3072", "rsa4096", "ec256")

_NOT_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
_NOT_AFTER = dt.datetime(2060, 1, 1, tzinfo=dt.UTC)


def make_key(key_type: str):
    if key_type.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[3:]))
    if key_type == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"unknown key_type {key_type!r}")


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _builder(subject: str, issuer: str, public_key) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
    )


def _ca_cert(subject, issuer, public_key, signing_key, path_length):
    builder = (
        _builder(subject, issuer, public_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        # Python 3.13+ verifies with VERIFY_X509_STRICT, which requires an AKI (real LE intermediates have one).
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
    )
    return builder.sign(signing_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_to_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class Pki:
    root_key: rsa.RSAPrivateKey
    root_cert: x509.Certificate
    intermediate_key: rsa.RSAPrivateKey
    intermediate_cert: x509.Certificate

    @property
    def root_pem(self) -> bytes:
        return pem(self.root_cert)

    @property
    def root_der(self) -> bytes:
        return der(self.root_cert)

    @property
    def intermediate_pem(self) -> bytes:
        return pem(self.intermediate_cert)

    @property
    def intermediate_der(self) -> bytes:
        return der(self.intermediate_cert)

    def issue(self, name: str = "localhost", key_type: str = "rsa2048") -> tuple[bytes, bytes]:
        """Issue a fresh leaf (new key every call) signed by the intermediate: (cert_pem, key_pem)."""
        key = make_key(key_type)
        cert = (
            _builder(name, "Test Intermediate CA", key.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=isinstance(key, rsa.RSAPrivateKey),
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                    + ([x509.DNSName(name)] if name != "localhost" else [])
                ),
                critical=False,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .sign(self.intermediate_key, hashes.SHA256())
        )
        return pem(cert), key_to_pem(key)


@pytest.fixture(scope="session")
def pki() -> Pki:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _ca_cert("Test Root CA", "Test Root CA", root_key.public_key(), root_key, path_length=1)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter = _ca_cert("Test Intermediate CA", "Test Root CA", int_key.public_key(), root_key, path_length=0)
    return Pki(root_key, root, int_key, inter)


@dataclass(frozen=True)
class OldCert:
    cert_pem: bytes
    key_pem: bytes
    der: bytes


@pytest.fixture(scope="session")
def old_cert() -> OldCert:
    """A self-signed CN=ArkKVM self-signed RSA certificate for localhost, like the KVM's factory one."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        _builder("ArkKVM self-signed", "ArkKVM self-signed", key.public_key())
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return OldCert(pem(cert), key_to_pem(key), der(cert))


@pytest.fixture
def make_lineage(tmp_path: Path, pki: Pki) -> Callable[..., Path]:
    """Factory: make_lineage(name="kvm.example.com", key_type="rsa2048") -> live/<name> folder."""

    def _make(name: str = "kvm.example.com", key_type: str = "rsa2048") -> Path:
        cert_pem, key_pem = pki.issue("localhost", key_type)
        d = tmp_path / "live" / name
        d.mkdir(parents=True)
        (d / "cert.pem").write_bytes(cert_pem)
        (d / "chain.pem").write_bytes(pki.intermediate_pem)
        (d / "fullchain.pem").write_bytes(cert_pem + pki.intermediate_pem)
        (d / "privkey.pem").write_bytes(key_pem)
        return d

    return _make


@pytest.fixture
def lineage_dir(make_lineage: Callable[..., Path], request: pytest.FixtureRequest) -> Path:
    """A certbot-style live/<name> folder. Parametrize indirectly to pick the key type."""
    return make_lineage(key_type=getattr(request, "param", "rsa2048"))
