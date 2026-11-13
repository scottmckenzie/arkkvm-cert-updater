"""Tests for the command-line interface: options, lineage selection, exit codes and logging."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from arkkvm_cert_updater import cli
from arkkvm_cert_updater.certs import CertificateError
from arkkvm_cert_updater.config import ConfigError
from arkkvm_cert_updater.device import DeviceError, LoginError, ProtocolError, RefusedError
from arkkvm_cert_updater.tls import IdentityError
from arkkvm_cert_updater.updater import Deps, Outcome, VerifyError

SECRET = "hunter2-secret"


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        "HOME": str(tmp_path),
        "ARKKVM_URL": "https://kvm.test",
        "ARKKVM_PASSWORD": SECRET,
        "ARKKVM_CERT_NAME": "kvm.test",
        "ARKKVM_LETSENCRYPT_LIVE": str(tmp_path / "live"),
    }


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Replace lineage loading and the install flow; record what the CLI asked for."""
    record: dict = {"run": [], "paths": [], "outcome": Outcome.INSTALLED, "raises": None}

    def fake_load(path: Path):
        record["paths"].append(path)
        return "LINEAGE"

    def fake_run(config, lineage, **kwargs):
        record["run"].append(kwargs)
        if record["raises"] is not None:
            raise record["raises"]
        return record["outcome"]

    monkeypatch.setattr(cli, "load_lineage", fake_load)
    monkeypatch.setattr(cli, "run", fake_run)
    return record


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (ConfigError("bad config"), 2),
        (CertificateError("bad cert"), 3),
        (IdentityError("wrong identity"), 4),
        (LoginError("login failed"), 5),
        (RefusedError("refused"), 6),
        (VerifyError("not verified"), 7),
        (ProtocolError("protocol"), 8),
        (DeviceError("generic"), 8),
        (ConnectionRefusedError("no route"), 8),
    ],
)
def test_exit_codes(exc, code, env, calls, capsys):
    calls["raises"] = exc
    assert cli.main([], env) == code
    err = capsys.readouterr().err
    assert [line for line in err.splitlines() if line.startswith("error:")] == [f"error: {exc}"]
    assert "Traceback" not in err


def test_verbose_shows_traceback(env, calls, capsys):
    calls["raises"] = LoginError("login failed")
    assert cli.main(["-v"], env) == 5
    assert "Traceback" in capsys.readouterr().err


def test_unexpected_exception_propagates(env, calls):
    calls["raises"] = RuntimeError("bug")
    with pytest.raises(RuntimeError):
        cli.main([], env)


def test_config_error_from_settings(env, calls, capsys):
    del env["ARKKVM_URL"]
    assert cli.main([], env) == 2
    assert "error: ARKKVM_URL is required" in capsys.readouterr().err
    assert calls["run"] == []


@pytest.mark.parametrize("outcome", list(Outcome))
def test_success_outcomes_exit_zero(outcome, env, calls, caplog):
    calls["outcome"] = outcome
    with caplog.at_level(logging.INFO, logger="arkkvm_cert_updater"):
        assert cli.main([], env) == 0
    assert [r for r in caplog.records if r.name == "arkkvm_cert_updater" and r.levelno == logging.INFO]


def test_certbot_wrong_lineage_skips(env, calls, caplog):
    env["RENEWED_LINEAGE"] = "/x/live/other.example"
    with caplog.at_level(logging.INFO, logger="arkkvm_cert_updater"):
        assert cli.main(["--certbot"], env) == 0
    assert "not the KVM certificate; skipping" in caplog.text
    assert calls["run"] == [] and calls["paths"] == []


def test_certbot_matching_lineage(env, calls):
    env["RENEWED_LINEAGE"] = "/x/live/kvm.test"
    assert cli.main(["--certbot"], env) == 0
    assert calls["paths"] == [Path("/x/live/kvm.test")]


def test_certbot_requires_renewed_lineage(env, calls, capsys):
    assert cli.main(["--certbot"], env) == 2
    assert "RENEWED_LINEAGE" in capsys.readouterr().err
    assert calls["run"] == []


def test_default_lineage_from_live_dir(env, calls, tmp_path):
    assert cli.main([], env) == 0
    assert calls["paths"] == [tmp_path / "live" / "kvm.test"]


def test_explicit_lineage(env, calls):
    assert cli.main(["--lineage", "/some/where"], env) == 0
    assert calls["paths"] == [Path("/some/where")]


def test_env_file_option(env, calls, tmp_path):
    env_file = tmp_path / "x.env"
    env_file.write_text("ARKKVM_CERT_NAME=from-file\n")
    env_file.chmod(0o600)
    del env["ARKKVM_CERT_NAME"]
    assert cli.main(["--env-file", str(env_file)], env) == 0
    assert calls["paths"] == [tmp_path / "live" / "from-file"]


def test_no_password_option():
    options = [opt for action in cli.build_parser()._actions for opt in action.option_strings]
    assert options
    assert not [opt for opt in options if "password" in opt]


def test_check_passes_check_only(env, calls):
    calls["outcome"] = Outcome.CHECKED
    assert cli.main(["--check"], env) == 0
    assert calls["run"] == [{"force": False, "check_only": True, "deps": None}]


def test_force_passes_force(env, calls):
    assert cli.main(["--force"], env) == 0
    assert calls["run"] == [{"force": True, "check_only": False, "deps": None}]


def test_verbose_does_not_enable_webrtc_logging(env, calls):
    pkg = logging.getLogger("arkkvm_cert_updater")
    old = pkg.level
    try:
        assert cli.main(["-v"], env) == 0
        assert pkg.level == logging.DEBUG
        for name in ("aioice", "aiortc"):
            assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING
    finally:
        pkg.setLevel(old)


def test_error_line_has_no_secrets(env, calls, capsys):
    calls["raises"] = LoginError("login failed")
    cli.main([], env)
    assert SECRET not in capsys.readouterr().err


def test_protocol_error_message_has_no_traceback(env, calls, capsys):
    calls["raises"] = ProtocolError("unexpected redirect (HTTP 308)")
    assert cli.main([], env) == 8
    err = capsys.readouterr().err
    assert "redirect" in err and "Traceback" not in err


def test_unreachable_device_exits_8(env, make_lineage, capsys):
    make_lineage("kvm.test")

    def fetch(*args, **kwargs):
        raise ConnectionRefusedError("connection refused")

    deps = Deps(served=fetch)
    # The test certificate covers localhost, so the pre-install check passes and the KVM is contacted.
    assert cli.main([], {**env, "ARKKVM_URL": "https://localhost"}, deps=deps) == 8
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_certificate_not_covering_host_exits_3_before_contacting_device(env, make_lineage, capsys):
    make_lineage("kvm.test")  # issued for localhost / 127.0.0.1 only

    def fetch(*args, **kwargs):
        raise AssertionError("the KVM must not be contacted")

    assert cli.main(["--check"], env, deps=Deps(served=fetch)) == 3
    err = capsys.readouterr().err
    assert "does not cover kvm.test" in err and "ARKKVM_URL" in err


def test_no_password_option_rejected():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--password", "x"])


def test_unresolved_pass_reference_exits_2(env, calls, capsys):
    env["ARKKVM_PASSWORD"] = "pass://vault/item/password"
    assert cli.main([], env) == 2
    err = capsys.readouterr().err
    assert "Proton Pass" in err and "vault/item" not in err
    assert calls["run"] == []
