import argparse
import sys
import getpass
import types

import pytest

import arkkvm_update_cert as m


def run_main(monkeypatch, argv):
    """Set sys.argv and run the CLI entry point."""
    monkeypatch.setattr(sys, "argv", ["arkkvm_update_cert"] + argv)
    return m.main()


# ---------- normalise_base_url ----------

@pytest.mark.parametrize(
    "input_value,expected",
    [
        ("arkkvm.local", "http://arkkvm.local"),
        ("https://arkkvm.local/", "https://arkkvm.local"),
        ("http://10.0.0.5:8080/kvm/", "http://10.0.0.5:8080/kvm"),
    ],
)
def test_normalise_base_url_valid(input_value, expected):
    assert m.normalise_base_url(input_value) == expected


@pytest.mark.parametrize(
    "input_value",
    [
        "ftp://host",
        "http://",
        "http://host/?a=1",
        "http://host/#frag",
    ],
)
def test_normalise_base_url_invalid(input_value):
    with pytest.raises(argparse.ArgumentTypeError):
        m.normalise_base_url(input_value)


# ---------- parser.error cases ----------

@pytest.mark.parametrize(
    "argv",
    [
        ["host"],  # custom mode without cert/key
        ["host", "--mode", "disabled", "--cert", "c.pem"],
        ["host", "--mode", "disabled", "--no-password", "--password", "x"],
        ["host", "--mode", "disabled", "--no-password", "--insecure", "--ca-file", "ca.pem"],
        ["host", "--mode", "disabled", "--no-password", "--timeout", "0"],
    ],
)
def test_parser_error(monkeypatch, argv):
    with pytest.raises(SystemExit) as excinfo:
        run_main(monkeypatch, argv)
    assert excinfo.value.code == 2


# ---------- password resolution ----------

@pytest.fixture
def fake_update_device(monkeypatch):
    """Patch m.update_device to record the args passed."""
    recorded = []

    async def _fake_update_device(args):
        recorded.append(args)
        return None

    monkeypatch.setattr(m, "update_device", _fake_update_device)
    return recorded


def test_password_env(monkeypatch, fake_update_device):
    monkeypatch.setenv("ARKKVM_PASSWORD", "envpw")
    ret = run_main(monkeypatch, ["host", "--mode", "disabled"])
    assert ret == 0
    assert fake_update_device[0].password == "envpw"


def test_password_cli_overrides_env(monkeypatch, fake_update_device):
    monkeypatch.setenv("ARKKVM_PASSWORD", "envpw")
    ret = run_main(monkeypatch, ["host", "--mode", "disabled", "--password", "cli"])
    assert ret == 0
    assert fake_update_device[0].password == "cli"


def test_password_prompt(monkeypatch, fake_update_device):
    monkeypatch.delenv("ARKKVM_PASSWORD", raising=False)

    def fake_getpass(prompt):
        return "prompted"

    monkeypatch.setattr(m, "getpass", types.SimpleNamespace(getpass=fake_getpass))
    ret = run_main(monkeypatch, ["host", "--mode", "disabled"])
    assert ret == 0
    assert fake_update_device[0].password == "prompted"


def test_password_no_password(monkeypatch, fake_update_device):
    monkeypatch.delenv("ARKKVM_PASSWORD", raising=False)

    def fake_getpass(prompt):
        raise AssertionError("getpass should not be called")

    monkeypatch.setattr(m, "getpass", types.SimpleNamespace(getpass=fake_getpass))
    ret = run_main(monkeypatch, ["host", "--mode", "disabled", "--no-password"])
    assert ret == 0
    assert fake_update_device[0].password is None


# ---------- error mapping ----------

def test_error_mapping_arkkvm_error(monkeypatch, capsys):
    async def fake_update_device(args):
        raise m.ArkKVMError("boom")

    monkeypatch.setattr(m, "update_device", fake_update_device)
    monkeypatch.setenv("ARKKVM_PASSWORD", "envpw")
    ret = run_main(monkeypatch, ["host", "--mode", "disabled"])
    captured = capsys.readouterr()
    assert ret == 1
    assert "Error: boom" in captured.err


def test_error_mapping_keyboard_interrupt(monkeypatch, capsys):
    async def fake_update_device(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "update_device", fake_update_device)
    monkeypatch.setenv("ARKKVM_PASSWORD", "envpw")
    ret = run_main(monkeypatch, ["host", "--mode", "disabled"])
    captured = capsys.readouterr()
    assert ret == 130
    assert "Cancelled." in captured.err
