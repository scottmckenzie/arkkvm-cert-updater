"""Load and validate a certbot lineage (``live/<name>/``)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
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
    # Every intermediate certbot has kept for this lineage (archive/<name>/chain*.pem), the current ones
    # included. Only for verifying the certificate the KVM serves *before* an install, which may have been
    # issued under an earlier intermediate than the new one (Let's Encrypt rotates them).
    issuer_chains_pem: bytes = b""


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CertificateError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _cert_blocks(data: bytes, path: Path) -> list[bytes]:
    """Every PEM certificate block in ``data``, each checked to parse; errors name ``path``."""
    blocks = _CERT_BLOCK.findall(data)
    try:
        for block in blocks:
            block.decode("ascii")
            x509.load_pem_x509_certificate(block)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CertificateError(f"cannot parse {path}: {exc}") from exc
    return blocks


def _join(blocks: list[bytes]) -> bytes:
    return b"\n".join(blocks) + b"\n" if blocks else b""


def _archived_issuer_chains(chain_path: Path) -> bytes:
    """Intermediates from every ``chain*.pem`` next to the file ``chain_path`` points at.

    certbot's ``live/<name>/chain.pem`` is a symlink into ``archive/<name>/``, which keeps ``chainN.pem`` for
    every issue and renewal. Unreadable or malformed old files are skipped: these are only extra helpers for
    building a chain, never trust anchors.
    """
    try:
        archive = chain_path.resolve(strict=True).parent
    except OSError:
        return b""
    found: list[bytes] = []
    for old in sorted(archive.glob("chain*.pem")):
        try:
            blocks = _cert_blocks(old.read_bytes(), old)
        except (OSError, CertificateError):
            continue
        found.extend(b for b in blocks if b not in found)
    return _join(found)


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

    blocks = _cert_blocks(fullchain, fullchain_path)
    if not blocks:
        raise CertificateError(f"no certificate found in {fullchain_path}")
    leaf = x509.load_pem_x509_certificate(blocks[0])
    chain_blocks = _cert_blocks(chain_pem, chain_path)
    if chain_pem.strip() and not chain_blocks:
        raise CertificateError(f"no certificate found in {chain_path}")

    try:
        key_text = key_pem.decode("ascii").strip() + "\n"
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
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
        key_pem=key_text,
        chain_pem=_join(chain_blocks),
        fingerprint=sha256_fingerprint(leaf_der),
        issuer_chains_pem=_archived_issuer_chains(chain_path) or _join(chain_blocks),
    )


def _covers(leaf: x509.Certificate, host: str) -> bool:
    """Whether the certificate's subjectAltName covers ``host`` (a DNS name or an IP literal)."""
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return ip in san.get_values_for_type(x509.IPAddress)
    host = host.lower().rstrip(".")
    for name in san.get_values_for_type(x509.DNSName):
        name = name.lower().rstrip(".")
        if name == host:
            return True
        # A wildcard covers exactly one leftmost label: *.example.com covers a.example.com only.
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def check_usable_for(lineage: Lineage, host: str, *, now: datetime | None = None) -> None:
    """Refuse a certificate the KVM could not serve successfully for ``host``, before anything is installed.

    Installing it would reboot the KVM into a certificate that fails verification afterwards, and the
    first-install pin would no longer match either. Trust is checked by the CA; this catches the
    configuration mistakes: a URL name the certificate doesn't cover, or an expired lineage.
    """
    leaf = x509.load_der_x509_certificate(lineage.leaf_der)
    now = now or datetime.now(UTC)
    if now < leaf.not_valid_before_utc:
        raise CertificateError(f"the certificate for {lineage.name} is not valid until {leaf.not_valid_before_utc}")
    if now > leaf.not_valid_after_utc:
        raise CertificateError(f"the certificate for {lineage.name} expired on {leaf.not_valid_after_utc}")
    if not _covers(leaf, host):
        raise CertificateError(
            f"the certificate for {lineage.name} does not cover {host}; set ARKKVM_URL to a name it was issued for"
        )
