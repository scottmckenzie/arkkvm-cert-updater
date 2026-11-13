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


# chain.pem -------------------------------------------------------------------


def test_malformed_chain_is_a_certificate_error(make_lineage):
    lineage = make_lineage()
    (lineage / "chain.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")
    with pytest.raises(CertificateError, match=r"chain\.pem"):
        load_lineage(lineage)


def test_non_ascii_chain_is_a_certificate_error(make_lineage):
    lineage = make_lineage()
    (lineage / "chain.pem").write_bytes("-----BEGIN CERTIFICATE-----\nMIIé\n-----END CERTIFICATE-----\n".encode())
    with pytest.raises(CertificateError, match=r"chain\.pem"):
        load_lineage(lineage)


def test_chain_without_certificates_is_a_certificate_error(make_lineage):
    lineage = make_lineage()
    (lineage / "chain.pem").write_bytes(b"just some text\n")
    with pytest.raises(CertificateError, match=r"no certificate found in .*chain\.pem"):
        load_lineage(lineage)


# issuer chains from certbot's archive ------------------------------------------


def test_issuer_chains_include_every_archived_intermediate(pki, tmp_path):
    from conftest import certbot_lineage, second_intermediate

    pki_b = second_intermediate(pki)
    old_cert, old_key = pki.issue()
    new_cert, new_key = pki_b.issue()
    live = certbot_lineage(
        tmp_path,
        "kvm.example.com",
        [(old_cert, old_key, pki.intermediate_pem), (new_cert, new_key, pki_b.intermediate_pem)],
    )
    (live.parent.parent / "archive" / "kvm.example.com" / "chain0.pem").write_bytes(b"garbage, skipped\n")
    lineage = load_lineage(live)
    assert lineage.chain_pem.strip() == pki_b.intermediate_pem.strip()  # the current chain only
    assert pki.intermediate_pem.strip() in lineage.issuer_chains_pem
    assert pki_b.intermediate_pem.strip() in lineage.issuer_chains_pem
    assert lineage.issuer_chains_pem.count(b"BEGIN CERTIFICATE") == 2


def test_issuer_chains_without_archive_are_the_current_chain(make_lineage, pki):
    lineage = load_lineage(make_lineage())  # plain files, no symlinks
    assert lineage.issuer_chains_pem.strip() == pki.intermediate_pem.strip()


# check_usable_for -------------------------------------------------------------


def _lineage_for(pki, tmp_path, name: str, *, sans=None, not_before=None, not_after=None):
    """A lineage whose leaf has exactly the given subjectAltNames and validity (defaults: 2020 to 2060)."""
    import datetime as dt

    from conftest import key_to_pem, make_key, pem
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = make_key("ec256")
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(pki.intermediate_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(not_after or dt.datetime(2060, 1, 1, tzinfo=dt.UTC))
    )
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(pki.intermediate_key, hashes.SHA256())
    d = tmp_path / "live" / name
    d.mkdir(parents=True)
    (d / "fullchain.pem").write_bytes(pem(cert) + pki.intermediate_pem)
    (d / "chain.pem").write_bytes(pki.intermediate_pem)
    (d / "privkey.pem").write_bytes(key_to_pem(key))
    return load_lineage(d)


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("kvm.example.com", True),
        ("KVM.Example.COM", True),
        ("kvm.example.com.", True),
        ("a.wild.example", True),
        ("wild.example", False),  # a wildcard needs exactly one more label
        ("a.b.wild.example", False),
        ("other.example.com", False),
        ("192.0.2.7", True),
        ("192.0.2.8", False),
        ("2001:db8::1", True),
    ],
)
def test_check_usable_for_host(pki, tmp_path, host, ok):
    import ipaddress

    from cryptography import x509

    from arkkvm_cert_updater.certs import check_usable_for

    sans = [
        x509.DNSName("kvm.example.com"),
        x509.DNSName("*.wild.example"),
        x509.IPAddress(ipaddress.ip_address("192.0.2.7")),
        x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
    ]
    lineage = _lineage_for(pki, tmp_path, "kvm.example.com", sans=sans)
    if ok:
        check_usable_for(lineage, host)
    else:
        with pytest.raises(CertificateError, match="does not cover"):
            check_usable_for(lineage, host)


def test_check_usable_for_ip_url_with_dns_only_certificate(pki, tmp_path):
    """Copilot's case: a factory-cert pin plus an IP-literal URL, but a DNS-only Let's Encrypt lineage."""
    from cryptography import x509

    from arkkvm_cert_updater.certs import check_usable_for

    lineage = _lineage_for(pki, tmp_path, "kvm.example.com", sans=[x509.DNSName("kvm.example.com")])
    with pytest.raises(CertificateError, match=r"does not cover 192\.0\.2\.7.*ARKKVM_URL"):
        check_usable_for(lineage, "192.0.2.7")


def test_check_usable_for_without_san(pki, tmp_path):
    from arkkvm_cert_updater.certs import check_usable_for

    lineage = _lineage_for(pki, tmp_path, "kvm.example.com")  # CN only: not enough for modern TLS clients
    with pytest.raises(CertificateError, match="does not cover"):
        check_usable_for(lineage, "kvm.example.com")


def test_check_usable_for_dates(pki, tmp_path):
    import datetime as dt

    from cryptography import x509

    from arkkvm_cert_updater.certs import check_usable_for

    san = [x509.DNSName("kvm.example.com")]
    start = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    end = dt.datetime(2026, 4, 1, tzinfo=dt.UTC)
    lineage = _lineage_for(pki, tmp_path, "kvm.example.com", sans=san, not_before=start, not_after=end)
    check_usable_for(lineage, "kvm.example.com", now=dt.datetime(2026, 2, 1, tzinfo=dt.UTC))
    with pytest.raises(CertificateError, match="expired"):
        check_usable_for(lineage, "kvm.example.com", now=dt.datetime(2026, 5, 1, tzinfo=dt.UTC))
    with pytest.raises(CertificateError, match="not valid until"):
        check_usable_for(lineage, "kvm.example.com", now=dt.datetime(2025, 12, 1, tzinfo=dt.UTC))
