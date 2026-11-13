"""Load and validate a certbot lineage (``live/<name>/``)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_CERT_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class CertificateError(Exception):
    """Raised when the lineage is unreadable or the certificate is unsuitable for the KVM."""


def sha256_fingerprint(der: bytes) -> bytes:
    return hashlib.sha256(der).digest()


def format_fingerprint(fp: bytes) -> str:
    return ":".join(f"{b:02X}" for b in fp)


@dataclass(frozen=True)
class Lineage:
    name: str
    leaf_der: bytes
    certs_pem: str
    key_pem: str
    chain_pem: bytes
    fingerprint: bytes


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CertificateError(f"cannot read {path}: {exc.strerror or exc}") from exc


def load_lineage(path: Path) -> Lineage:
    """Read cert files from a certbot lineage folder and check the key matches the certificate."""
    if not path.is_dir():
        raise CertificateError(f"certificate folder {path} does not exist or is not a directory")

    fullchain_path = path / "fullchain.pem"
    key_path = path / "privkey.pem"
    chain_path = path / "chain.pem"
    fullchain = _read(fullchain_path)
    key_pem = _read(key_path)
    chain_pem = _read(chain_path)

    blocks = _CERT_BLOCK.findall(fullchain)
    if not blocks:
        raise CertificateError(f"no certificate found in {fullchain_path}")
    try:
        leaf = x509.load_pem_x509_certificate(blocks[0])
        for block in blocks[1:]:
            x509.load_pem_x509_certificate(block)
    except ValueError as exc:
        raise CertificateError(f"cannot parse {fullchain_path}: {exc}") from exc

    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise CertificateError(f"cannot load private key {key_path} (it must be unencrypted PEM): {exc}") from exc

    pub = leaf.public_key()
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, spki) != pub.public_bytes(
        serialization.Encoding.DER, spki
    ):
        raise CertificateError(f"the private key {key_path} does not match the certificate in {fullchain_path}")

    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    return Lineage(
        name=path.name,
        leaf_der=leaf_der,
        certs_pem=b"\n".join(blocks).decode("ascii") + "\n",
        key_pem=key_pem.decode("ascii").strip() + "\n",
        chain_pem=chain_pem,
        fingerprint=sha256_fingerprint(leaf_der),
    )
