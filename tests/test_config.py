import logging
import os
from pathlib import Path

import pytest

from arkkvm_cert_updater import config
from arkkvm_cert_updater.config import (
    ConfigError,
    check_env_file_permissions,
    find_env_file,
    load_env,
    parse_env_file,
    resolve_config,
)

FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
BASE = {
    "ARKKVM_URL": "https://kvm.example.com",
    "ARKKVM_PASSWORD": "pw",
    "ARKKVM_CERT_NAME": "kvm.example.com",
}


@pytest.fixture(autouse=True)
def clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("ARKKVM_CERT_UPDATER_ENV", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def test_parse_env_file_formats(tmp_path: Path):
    path = tmp_path / "c.env"
    path.write_text("export A=\"x y\"\nB='z'\n# c=1\n\nD = e\n")
    assert parse_env_file(path) == {"A": "x y", "B": "z", "D": "e"}


def test_parse_env_file_rejects_bad_line(tmp_path: Path):
    path = tmp_path / "c.env"
    path.write_text("nonsense\n")
    with pytest.raises(ConfigError, match=r"c\.env:1"):
        parse_env_file(path)


def test_find_env_file_order(tmp_path: Path):
    home = tmp_path / "home"
    assert find_env_file({"HOME": str(home)}) is None
    assert find_env_file({"HOME": str(home), "XDG_CONFIG_HOME": "relative"}) is None
    user_file = home / ".config" / "arkkvm-cert-updater" / "config.env"
    user_file.parent.mkdir(parents=True)
    user_file.write_text("")
    assert find_env_file({"HOME": str(home)}) == user_file
    assert find_env_file({"HOME": str(home), "XDG_CONFIG_HOME": "relative"}) == user_file
    explicit = tmp_path / "other.env"
    assert find_env_file({"HOME": str(home), "ARKKVM_CERT_UPDATER_ENV": str(explicit)}) == explicit
    xdg = tmp_path / "xdg"
    assert config.user_config_dir({"XDG_CONFIG_HOME": str(xdg)}) == xdg / "arkkvm-cert-updater"


def test_user_config_dir_falls_back_to_path_home():
    assert config.user_config_dir({}) == Path.home() / ".config" / "arkkvm-cert-updater"


def test_environment_overrides_file(tmp_path: Path):
    path = tmp_path / "c.env"
    path.write_text("A=file\nB=file\n")
    path.chmod(0o600)
    assert load_env(path, {"B": "env", "C": "env"}) == {"A": "file", "B": "env", "C": "env"}


def test_load_env_without_file():
    assert load_env(None, {"A": "1"}) == {"A": "1"}


def test_load_env_missing_file(tmp_path: Path):
    with pytest.raises(ConfigError, match="cannot read env file"):
        load_env(tmp_path / "gone.env", {})


def test_resolve_minimal():
    cfg = resolve_config(BASE)
    assert cfg.url == "https://kvm.example.com"
    assert cfg.host == "kvm.example.com"
    assert cfg.port == 443
    assert cfg.timeout == 20
    assert cfg.password == "pw"
    assert cfg.cert_name == "kvm.example.com"
    assert cfg.reset_timeout == 300
    assert cfg.live_dir == Path(os.environ["HOME"]) / ".config/letsencrypt/live"
    assert cfg.tls_fingerprint is None
    assert cfg.ca_bundle is None


def test_resolve_port_and_ipv6():
    cfg = resolve_config({**BASE, "ARKKVM_URL": "https://[fd00::1]:8443"})
    assert cfg.host == "fd00::1"
    assert cfg.port == 8443


def test_resolve_fingerprint():
    expected = bytes.fromhex(FINGERPRINT.replace(":", ""))
    assert len(expected) == 32
    assert resolve_config({**BASE, "ARKKVM_TLS_FINGERPRINT": FINGERPRINT}).tls_fingerprint == expected
    plain = FINGERPRINT.replace(":", "").lower()
    assert resolve_config({**BASE, "ARKKVM_TLS_FINGERPRINT": plain}).tls_fingerprint == expected


def test_resolve_optional_settings(tmp_path: Path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    live = tmp_path / "live"
    cfg = resolve_config(
        {**BASE, "ARKKVM_CA_BUNDLE": str(bundle), "ARKKVM_LETSENCRYPT_LIVE": str(live), "ARKKVM_RESET_TIMEOUT": "12.5"}
    )
    assert cfg.ca_bundle == bundle
    assert cfg.live_dir == live
    assert cfg.reset_timeout == 12.5


def _without(name: str) -> dict[str, str]:
    return {k: v for k, v in BASE.items() if k != name}


@pytest.mark.parametrize(
    ("env", "setting"),
    [
        ({**BASE, "ARKKVM_URL": "http://x"}, "ARKKVM_URL"),
        ({**BASE, "ARKKVM_URL": "https://x/path"}, "ARKKVM_URL"),
        ({**BASE, "ARKKVM_URL": "https://"}, "ARKKVM_URL"),
        (_without("ARKKVM_URL"), "ARKKVM_URL"),
        (_without("ARKKVM_PASSWORD"), "ARKKVM_PASSWORD"),
        (_without("ARKKVM_CERT_NAME"), "ARKKVM_CERT_NAME"),
        ({**BASE, "ARKKVM_TLS_FINGERPRINT": "AB:CD"}, "ARKKVM_TLS_FINGERPRINT"),
        ({**BASE, "ARKKVM_TLS_FINGERPRINT": "zz" * 32}, "ARKKVM_TLS_FINGERPRINT"),
        ({**BASE, "ARKKVM_RESET_TIMEOUT": "0"}, "ARKKVM_RESET_TIMEOUT"),
        ({**BASE, "ARKKVM_RESET_TIMEOUT": "abc"}, "ARKKVM_RESET_TIMEOUT"),
        ({**BASE, "ARKKVM_TIMEOUT": "0"}, "ARKKVM_TIMEOUT"),
        ({**BASE, "ARKKVM_CA_BUNDLE": "/nonexistent/ca.pem"}, "ARKKVM_CA_BUNDLE"),
        ({**BASE, "ARKKVM_LETSENCRYPT_LIVE": "relative/live"}, "ARKKVM_LETSENCRYPT_LIVE"),
    ],
)
def test_resolve_rejects(env: dict[str, str], setting: str):
    with pytest.raises(ConfigError, match=setting):
        resolve_config(env)


def test_permission_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.WARNING)
    path = tmp_path / "c.env"
    path.write_text("A=1\n")
    path.chmod(0o644)
    check_env_file_permissions(path)
    assert "chmod 600" in caplog.text

    caplog.clear()
    path.chmod(0o600)
    check_env_file_permissions(path)
    assert caplog.text == ""

    # Fake the file's owner rather than the current user: files owned by root are
    # accepted, so faking getuid alone fails when the tests run as root.
    fields = list(path.stat())
    fields[4] = 12345  # st_uid
    fake = os.stat_result(fields)
    real_stat = Path.stat
    monkeypatch.setattr(Path, "stat", lambda self, **kw: fake if self == path else real_stat(self, **kw))
    monkeypatch.setattr(config.os, "getuid", lambda: 1000)
    check_env_file_permissions(path)
    assert "owned by another user (uid 12345)" in caplog.text


def test_permission_check_ignores_missing_file(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    check_env_file_permissions(tmp_path / "gone.env")
    assert caplog.text == ""


def test_secrets_not_in_errors():
    with pytest.raises(ConfigError) as info:
        resolve_config({**BASE, "ARKKVM_PASSWORD": "s3cret-value", "ARKKVM_RESET_TIMEOUT": "abc"})
    assert "s3cret-value" not in str(info.value)


def test_unresolved_pass_reference_rejected():
    ref = "pass://Private/kvm-item/password"
    with pytest.raises(ConfigError, match="unresolved Proton Pass reference") as exc:
        resolve_config({**BASE, "ARKKVM_PASSWORD": ref})
    assert ref not in str(exc.value)
    assert "Private/kvm-item" not in str(exc.value)
    assert "token" in str(exc.value)


def test_url_must_be_https():
    with pytest.raises(ConfigError, match=r"https://"):
        resolve_config({**BASE, "ARKKVM_URL": "http://kvm"})


def test_url_trailing_slash_normalised():
    cfg = resolve_config({**BASE, "ARKKVM_URL": "https://kvm.example.com/"})
    assert cfg.url == "https://kvm.example.com"
    assert cfg.port == 443


def test_url_keeps_port_and_ipv6_brackets():
    assert resolve_config({**BASE, "ARKKVM_URL": "https://[fd00::1]:8443/"}).url == "https://[fd00::1]:8443"


def test_timeout_default_and_custom():
    assert resolve_config(BASE).timeout == 20.0
    assert resolve_config({**BASE, "ARKKVM_TIMEOUT": "5"}).timeout == 5.0
    for bad in ("0", "-1", "nan", "x"):
        with pytest.raises(ConfigError, match="ARKKVM_TIMEOUT"):
            resolve_config({**BASE, "ARKKVM_TIMEOUT": bad})


def test_password_with_special_characters(tmp_path: Path):
    path = tmp_path / "c.env"
    path.write_text("ARKKVM_PASSWORD='p#ss=\"x\"=y'\n")
    env = parse_env_file(path)
    assert resolve_config({**BASE, **env}).password == 'p#ss="x"=y'


def test_unresolved_pass_reference_not_echoed():
    with pytest.raises(ConfigError) as exc:
        resolve_config({**BASE, "ARKKVM_PASSWORD": "pass://Vault/Item/password"})
    assert "Vault" not in str(exc.value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://KVM.Example.COM", "https://kvm.example.com"),
        ("https://kvm:443", "https://kvm"),
        ("https://kvm:", "https://kvm"),
        ("https://[FD00::1]", "https://[fd00::1]"),
        ("https://[fd00::1]:443/", "https://[fd00::1]"),
        ("https://kvm:8443", "https://kvm:8443"),
    ],
)
def test_url_normalised_from_host_and_port(raw, expected):
    assert resolve_config({**BASE, "ARKKVM_URL": raw}).url == expected


def test_url_port_zero_rejected():
    with pytest.raises(ConfigError, match="ARKKVM_URL"):
        resolve_config({**BASE, "ARKKVM_URL": "https://kvm:0"})
