import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import arkkvm_update_cert as m


def make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def make_cert(key: ec.EllipticCurvePrivateKey, cn: str = "arkkvm.example.com") -> str:
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> str:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return (
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        .decode()
    )


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_matching_cert_and_key(tmp_path: Path):
    key = make_key()
    cert_pem = make_cert(key)
    key_pem_text = key_pem(key)

    cert_path = write(tmp_path, "cert.pem", cert_pem)
    key_path = write(tmp_path, "key.pem", key_pem_text)

    result = m.load_custom_material(cert_path, key_path)
    expected = (cert_pem.strip() + "\n", key_pem_text.strip() + "\n")
    assert result == expected


def test_chain_file_with_leaf_key(tmp_path: Path):
    leaf_key = make_key()
    leaf_cert = make_cert(leaf_key, cn="leaf.example.com")
    second_key = make_key()
    second_cert = make_cert(second_key, cn="second.example.com")

    chain_text = leaf_cert + second_cert
    cert_path = write(tmp_path, "chain.pem", chain_text)
    key_path = write(tmp_path, "leaf_key.pem", key_pem(leaf_key))

    result = m.load_custom_material(cert_path, key_path)
    cert_out, key_out = result
    assert cert_out.count("-----BEGIN CERTIFICATE-----") == 2
    assert key_out == key_pem(leaf_key).strip() + "\n"


def test_missing_cert_file(tmp_path: Path):
    key = make_key()
    key_path = write(tmp_path, "key.pem", key_pem(key))
    missing_cert_path = tmp_path / "missing.pem"

    with pytest.raises(m.ArkKVMError, match="could not read certificate material"):
        m.load_custom_material(missing_cert_path, key_path)


def test_cert_file_without_pem(tmp_path: Path):
    key = make_key()
    key_path = write(tmp_path, "key.pem", key_pem(key))
    cert_path = write(tmp_path, "cert.txt", "hello")

    with pytest.raises(m.ArkKVMError, match="does not contain a PEM certificate"):
        m.load_custom_material(cert_path, key_path)


def test_key_file_without_private_key(tmp_path: Path):
    key = make_key()
    cert_pem = make_cert(key)
    cert_path = write(tmp_path, "cert.pem", cert_pem)
    key_path = write(tmp_path, "key.pem", cert_pem)  # write cert instead of key

    with pytest.raises(m.ArkKVMError, match="does not contain a PEM private key"):
        m.load_custom_material(cert_path, key_path)


def test_encrypted_key(tmp_path: Path):
    key = make_key()
    cert_pem = make_cert(key)
    cert_path = write(tmp_path, "cert.pem", cert_pem)
    key_path = write(tmp_path, "key.pem", key_pem(key, password=b"secret"))

    with pytest.raises(m.ArkKVMError, match="invalid or encrypted PEM material"):
        m.load_custom_material(cert_path, key_path)


def test_corrupt_cert_body(tmp_path: Path):
    key = make_key()
    cert_path = write(
        tmp_path,
        "cert.pem",
        "-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n",
    )
    key_path = write(tmp_path, "key.pem", key_pem(key))

    with pytest.raises(m.ArkKVMError, match="invalid or encrypted PEM material"):
        m.load_custom_material(cert_path, key_path)


def test_cert_and_key_do_not_match(tmp_path: Path):
    key1 = make_key()
    key2 = make_key()
    cert_pem = make_cert(key1)
    cert_path = write(tmp_path, "cert.pem", cert_pem)
    key_path = write(tmp_path, "key.pem", key_pem(key2))

    with pytest.raises(m.ArkKVMError, match="do not match"):
        m.load_custom_material(cert_path, key_path)
