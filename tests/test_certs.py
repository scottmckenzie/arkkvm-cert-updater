from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from arkkvm_cert_updater.certs import CertificateError, format_fingerprint, load_lineage, sha256_fingerprint


def test_load_lineage_ok(lineage_dir, pki):
    lin = load_lineage(lineage_dir)
    assert lin.name == "kvm.example.com"
    assert lin.fingerprint == hashlib.sha256(lin.leaf_der).digest()
    assert lin.fingerprint == sha256_fingerprint(lin.leaf_der)
    assert lin.certs_pem.count("BEGIN CERTIFICATE") == 2
    assert lin.certs_pem.endswith("\n")
    assert pki.intermediate_pem in lin.chain_pem
    assert lin.key_pem == (lineage_dir / "privkey.pem").read_text().strip() + "\n"


@pytest.mark.parametrize("key_type", ["ec256", "rsa2048", "rsa4096"])
def test_accepts_ec_and_rsa_keys(make_lineage, key_type):
    lin = load_lineage(make_lineage(key_type=key_type))
    assert lin.certs_pem.startswith("-----BEGIN CERTIFICATE-----") and lin.certs_pem.endswith("\n")


def test_certs_pem_strips_non_certificate_blocks(lineage_dir):
    full = lineage_dir / "fullchain.pem"
    full.write_bytes(full.read_bytes() + b"-----BEGIN DH PARAMETERS-----\nAAAA\n-----END DH PARAMETERS-----\n")
    lin = load_lineage(lineage_dir)
    assert "DH PARAMETERS" not in lin.certs_pem
    assert lin.certs_pem.count("BEGIN CERTIFICATE") == 2


def test_accepts_traditional_rsa_key(lineage_dir):
    priv = serialization.load_pem_private_key((lineage_dir / "privkey.pem").read_bytes(), None)
    trad = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    (lineage_dir / "privkey.pem").write_bytes(trad)
    assert load_lineage(lineage_dir).key_pem == trad.decode().strip() + "\n"


def test_rejects_mismatched_key(lineage_dir, pki):
    _, other_key = pki.issue()
    (lineage_dir / "privkey.pem").write_bytes(other_key)
    with pytest.raises(CertificateError, match="does not match"):
        load_lineage(lineage_dir)


def test_rejects_mismatched_key_type(lineage_dir, pki):
    _, other_key = pki.issue(key_type="ec256")
    (lineage_dir / "privkey.pem").write_bytes(other_key)
    with pytest.raises(CertificateError, match="does not match"):
        load_lineage(lineage_dir)


def test_rejects_encrypted_key(lineage_dir):
    priv = serialization.load_pem_private_key((lineage_dir / "privkey.pem").read_bytes(), None)
    enc = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    (lineage_dir / "privkey.pem").write_bytes(enc)
    with pytest.raises(CertificateError, match=r"privkey\.pem"):
        load_lineage(lineage_dir)


def test_rejects_certificate_in_place_of_key(lineage_dir):
    (lineage_dir / "privkey.pem").write_bytes((lineage_dir / "fullchain.pem").read_bytes())
    with pytest.raises(CertificateError, match=r"privkey\.pem"):
        load_lineage(lineage_dir)


def _missing_folder(d: Path) -> Path:
    return d.parent / "nope"


def _missing_chain(d: Path) -> Path:
    (d / "chain.pem").unlink()
    return d


def _missing_fullchain(d: Path) -> Path:
    (d / "fullchain.pem").unlink()
    return d


def _broken_symlink(d: Path) -> Path:
    (d / "privkey.pem").unlink()
    (d / "privkey.pem").symlink_to(d / "archive-gone.pem")
    return d


def _garbage_fullchain(d: Path) -> Path:
    (d / "fullchain.pem").write_bytes(b"not a certificate\n")
    return d


def _corrupt_cert_body(d: Path) -> Path:
    (d / "fullchain.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n")
    return d


def _garbage_key(d: Path) -> Path:
    (d / "privkey.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    return d


@pytest.mark.parametrize(
    ("break_it", "offender"),
    [
        (_missing_folder, "nope"),
        (_missing_chain, "chain.pem"),
        (_missing_fullchain, "fullchain.pem"),
        (_broken_symlink, "privkey.pem"),
        (_garbage_fullchain, "fullchain.pem"),
        (_corrupt_cert_body, "fullchain.pem"),
        (_garbage_key, "privkey.pem"),
    ],
)
def test_unreadable_lineage(lineage_dir, break_it, offender):
    path = break_it(lineage_dir)
    with pytest.raises(CertificateError) as exc:
        load_lineage(path)
    assert offender in str(exc.value)


def test_format_fingerprint():
    assert format_fingerprint(bytes.fromhex("8a62"))[:5] == "8A:62"
    assert format_fingerprint(bytes.fromhex("0a0b0c")) == "0A:0B:0C"
