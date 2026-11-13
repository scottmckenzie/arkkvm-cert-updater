"""Tests for certbot/arkkvm-deploy-hook.sh, using fake updater and pass-cli programs."""

import json
import os
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / "certbot" / "arkkvm-deploy-hook.sh"

# Fake updater: records its arguments and the environment variables we care about.
FAKE_BIN = """#!/bin/sh
python3 - "$@" <<'PY'
import json, os, sys
keys = ["RENEWED_LINEAGE", "ARKKVM_PASSWORD", "PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_PASS_KEY_PROVIDER", "PROTON_PASS_SESSION_DIR", "PROTON_PASS_AGENT_REASON"]
with open(os.environ["HOOK_TEST_LOG"], "a") as f:
    f.write(json.dumps({"prog": "updater", "argv": sys.argv[1:], "env": {k: os.environ.get(k) for k in keys}}) + "\\n")
PY
exit "${FAKE_BIN_EXIT:-0}"
"""

# Fake pass-cli. `run` "resolves" pass:// references by setting ARKKVM_PASSWORD, then
# runs the command. Each call logs its arguments, environment, and the --env-file contents.
FAKE_PASS = """#!/bin/sh
log() {
python3 - "$@" <<'PY'
import json, os, sys
keys = ["PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_PASS_KEY_PROVIDER", "PROTON_PASS_SESSION_DIR", "PROTON_PASS_AGENT_REASON"]
d = os.environ.get("PROTON_PASS_SESSION_DIR")
mode = oct(os.stat(d).st_mode & 0o777) if d and os.path.isdir(d) else None
argv = sys.argv[1:]
env_file = None
if "--env-file" in argv:
    with open(argv[argv.index("--env-file") + 1]) as ef:
        env_file = ef.read()
with open(os.environ["HOOK_TEST_LOG"], "a") as f:
    f.write(json.dumps({"prog": "pass-cli", "argv": argv, "env": {k: os.environ.get(k) for k in keys}, "session_mode": mode, "env_file": env_file}) + "\\n")
PY
}
log "$@"
case $1 in
    login) exit "${FAKE_LOGIN_EXIT:-0}" ;;
    logout) exit 0 ;;
    run)
        while [ "$1" != "--" ]; do shift; done
        shift
        ARKKVM_PASSWORD=resolved-secret exec "$@"
        ;;
esac
exit 99
"""


@pytest.fixture
def hook_env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("arkkvm-cert-updater", FAKE_BIN), ("pass-cli", FAKE_PASS)):
        prog = bindir / name
        prog.write_text(body)
        prog.chmod(0o755)
    (tmp_path / "tmp").mkdir()
    (tmp_path / "home").mkdir()
    live = tmp_path / "live" / "kvm.example.com"
    live.mkdir(parents=True)
    (tmp_path / "token").write_text("pst_abc::KEY\n")
    (tmp_path / "config.env").write_text(
        "ARKKVM_CERT_NAME=kvm.example.com\nARKKVM_PASSWORD=pass://Infra/ArkKVM/password\n"
    )
    return {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "TMPDIR": str(tmp_path / "tmp"),
        "HOOK_TEST_LOG": str(tmp_path / "log.jsonl"),
        "ARKKVM_CERT_UPDATER_ENV": str(tmp_path / "config.env"),
        "RENEWED_LINEAGE": str(live),
    }


def run_hook(env: dict[str, str], *args: str) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    result = subprocess.run([str(HOOK), *args], env=env, capture_output=True, text=True, timeout=30)
    log = Path(env["HOOK_TEST_LOG"])
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return result, calls


def config(env: dict[str, str], text: str, *, cert_name: bool = True) -> None:
    """Write the env file; ARKKVM_CERT_NAME is required by the hook, so add it unless the text has one."""
    if cert_name and "ARKKVM_CERT_NAME" not in text:
        text = "ARKKVM_CERT_NAME=kvm.example.com\n" + text
    Path(env["ARKKVM_CERT_UPDATER_ENV"]).write_text(text)


def test_without_proton_pass_runs_updater_directly(hook_env):
    result, calls = run_hook(hook_env, "-v")
    assert result.returncode == 0, result.stderr
    assert [c["prog"] for c in calls] == ["updater"]
    assert calls[0]["argv"] == ["--certbot", "--env-file", hook_env["ARKKVM_CERT_UPDATER_ENV"], "-v"]


def test_requires_lineage(hook_env):
    del hook_env["RENEWED_LINEAGE"]
    result, calls = run_hook(hook_env)
    assert result.returncode == 1
    assert "RENEWED_LINEAGE is not set" in result.stderr
    assert calls == []


def test_missing_updater(hook_env, tmp_path):
    (tmp_path / "bin" / "arkkvm-cert-updater").unlink()
    result, _ = run_hook(hook_env)
    assert result.returncode == 1
    assert "not found" in result.stderr


def test_proton_pass_with_token_file(hook_env, tmp_path):
    config(
        hook_env,
        f"ARKKVM_PASSWORD=pass://Infra/ArkKVM/password\nARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n",
    )
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr

    login, run, updater, logout = calls
    # A private throwaway session: never the user's own pass-cli session or keyring.
    session = login["env"]["PROTON_PASS_SESSION_DIR"]
    assert session and session.startswith(str(tmp_path / "tmp"))
    assert login["session_mode"] == "0o700"
    assert run["env"]["PROTON_PASS_SESSION_DIR"] == session == logout["env"]["PROTON_PASS_SESSION_DIR"]
    assert list((tmp_path / "tmp").iterdir()) == []  # everything removed afterwards
    # The token goes through the environment, never the command line.
    assert login["argv"] == ["login"]
    assert login["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "pst_abc::KEY"
    assert login["env"]["PROTON_PASS_KEY_PROVIDER"] == "fs"
    assert run["argv"][:2] == ["run", "--env-file"] and run["argv"][3] == "--"
    assert "pass://Infra/ArkKVM/password" in run["env_file"]
    assert run["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None  # not leaked to later commands
    assert updater["argv"][:3] == ["--certbot", "--env-file", run["argv"][2]]
    assert updater["env"]["ARKKVM_PASSWORD"] == "resolved-secret"
    assert updater["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None
    assert logout["argv"] == ["logout", "--force"]


def test_agent_token_and_reason_in_config(hook_env):
    config(
        hook_env,
        "ARKKVM_PASSWORD=pass://Infra/ArkKVM/password\n"
        'export PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_agent::AGENTKEY"\n'
        "PROTON_PASS_AGENT_REASON='Renew the ArkKVM certificate'\n",
    )
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    login, run, updater, _ = calls
    assert login["argv"] == ["login"]
    assert login["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "pst_agent::AGENTKEY"
    assert run["env"]["PROTON_PASS_AGENT_REASON"] == "Renew the ArkKVM certificate"
    # pass-cli run and the updater get a copy of config.env without the token.
    assert "pst_agent" not in run["env_file"]
    assert "pass://Infra/ArkKVM/password" in run["env_file"]
    assert "PROTON_PASS_AGENT_REASON" in run["env_file"]
    assert run["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None
    assert updater["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None


def test_agent_token_from_environment_is_not_passed_on(hook_env):
    hook_env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = "pst_env::KEY"
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    login, run, updater, _ = calls
    assert login["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "pst_env::KEY"
    assert run["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None
    assert updater["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] is None


def test_default_agent_reason_names_certificate(hook_env):
    config(hook_env, "PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_agent::KEY\n")
    _, calls = run_hook(hook_env)
    reason = calls[1]["env"]["PROTON_PASS_AGENT_REASON"]
    assert "kvm.example.com" in reason and len(reason) <= 300


def test_agent_reason_too_long(hook_env):
    config(hook_env, f"PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_agent::KEY\nPROTON_PASS_AGENT_REASON={'x' * 301}\n")
    result, calls = run_hook(hook_env)
    assert result.returncode == 1 and "300 characters" in result.stderr
    assert calls == []


def test_token_file_accepts_agent_create_output(hook_env, tmp_path):
    (tmp_path / "token").write_text("PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_agent::KEY\n")
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    _, calls = run_hook(hook_env)
    assert calls[0]["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "pst_agent::KEY"


def test_proton_pass_login_failure_stops(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    hook_env["FAKE_LOGIN_EXIT"] = "1"
    result, calls = run_hook(hook_env)
    assert result.returncode == 1
    assert "login failed" in result.stderr
    # The updater never runs; cleanup still logs out of the throwaway session.
    assert [c["argv"][0] for c in calls] == ["login", "logout"]


def test_proton_pass_updater_failure_propagates_and_logs_out(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    hook_env["FAKE_BIN_EXIT"] = "4"
    result, calls = run_hook(hook_env)
    assert result.returncode == 4
    assert calls[-1]["argv"] == ["logout", "--force"]
    assert not Path(calls[-1]["env"]["PROTON_PASS_SESSION_DIR"]).exists()


def test_proton_pass_unreadable_or_empty_token(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'missing'}\n")
    result, _ = run_hook(hook_env)
    assert result.returncode == 1 and "cannot read" in result.stderr

    (tmp_path / "empty").write_text("\n")
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'empty'}\n")
    result, _ = run_hook(hook_env)
    assert result.returncode == 1 and "empty" in result.stderr


def test_proton_pass_missing_pass_cli(hook_env, tmp_path):
    (tmp_path / "bin" / "pass-cli").unlink()
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    result, _ = run_hook(hook_env)
    assert result.returncode == 1 and "pass-cli not found" in result.stderr


def test_key_provider_is_always_fs_in_private_session(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    hook_env["PROTON_PASS_KEY_PROVIDER"] = "keyring"  # the user's own setting must not leak in
    hook_env["PROTON_PASS_SESSION_DIR"] = str(tmp_path / "users-own-session")
    _, calls = run_hook(hook_env)
    assert calls[0]["env"]["PROTON_PASS_KEY_PROVIDER"] == "fs"
    assert calls[0]["env"]["PROTON_PASS_SESSION_DIR"] != str(tmp_path / "users-own-session")


def test_login_failure_still_cleans_up_session(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    hook_env["FAKE_LOGIN_EXIT"] = "1"
    run_hook(hook_env)
    assert list((tmp_path / "tmp").iterdir()) == []


def test_config_parsing_quotes_export_comments_and_env_override(hook_env, tmp_path):
    other = tmp_path / "other-updater"
    other.write_text(FAKE_BIN)
    other.chmod(0o755)
    config(
        hook_env,
        "# ARKKVM_PASS_TOKEN_FILE=/should/be/ignored\n"
        f'export ARKKVM_UPDATER_BIN="{other}"   \n'
        "ARKKVM_CERT_NAME='kvm.example.com'\n"
        f"ARKKVM_LETSENCRYPT_LIVE = {tmp_path / 'live'}\n"
        "ARKKVM_PASS_TOKEN_FILE=\n",
    )
    del hook_env["RENEWED_LINEAGE"]
    result, calls = run_hook(hook_env, "--reapply")
    assert result.returncode == 0, result.stderr
    assert [c["prog"] for c in calls] == ["updater"]  # empty token file setting: no Proton Pass
    assert calls[0]["env"]["RENEWED_LINEAGE"] == str(tmp_path / "live" / "kvm.example.com")

    # A real environment variable beats the file.
    hook_env["ARKKVM_CERT_NAME"] = "missing.example.com"
    result, _ = run_hook(hook_env, "--reapply")
    assert result.returncode == 1 and "missing.example.com does not exist" in result.stderr


def test_requires_cert_name(hook_env):
    config(hook_env, "ARKKVM_PASSWORD=x\n", cert_name=False)
    for args in ((), ("--reapply",)):
        result, calls = run_hook(hook_env, *args)
        assert result.returncode == 1 and "ARKKVM_CERT_NAME" in result.stderr
        assert calls == []


def test_skips_other_certificate(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_PASS_TOKEN_FILE={tmp_path / 'token'}\n")
    hook_env["RENEWED_LINEAGE"] = str(tmp_path / "live" / "other.example")
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert "skipping" in result.stderr
    assert calls == []  # neither pass-cli nor the updater ran
    assert list((tmp_path / "tmp").iterdir()) == []


def test_no_config_found(hook_env):
    del hook_env["ARKKVM_CERT_UPDATER_ENV"]
    result, calls = run_hook(hook_env)
    assert result.returncode == 1
    assert "no config.env found" in result.stderr
    assert calls == []


def test_default_reason_names_arkkvm(hook_env):
    config(hook_env, "PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_agent::KEY\n")
    _, calls = run_hook(hook_env)
    reason = calls[1]["env"]["PROTON_PASS_AGENT_REASON"]
    assert reason == "arkkvm-cert-updater: install certificate kvm.example.com on the ArkKVM"


def test_reapply_passes_remaining_args(hook_env, tmp_path):
    config(hook_env, f"ARKKVM_CERT_NAME=kvm.example.com\nARKKVM_LETSENCRYPT_LIVE={tmp_path / 'live'}\n")
    result, calls = run_hook(hook_env, "--reapply", "-v")
    assert result.returncode == 0, result.stderr
    assert calls[0]["argv"][-1] == "-v" and "--reapply" not in calls[0]["argv"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script")
def test_hook_is_executable():
    assert os.access(HOOK, os.X_OK)


# --- config file location and defaults -------------------------------------------


def _user_config(home: Path, text: str) -> Path:
    path = home / ".config" / "arkkvm-cert-updater" / "config.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_finds_config_in_home(hook_env, tmp_path):
    del hook_env["ARKKVM_CERT_UPDATER_ENV"]
    path = _user_config(tmp_path / "home", "ARKKVM_CERT_NAME=kvm.example.com\n")
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert calls[0]["argv"][:3] == ["--certbot", "--env-file", str(path)]


def test_finds_config_in_xdg_config_home(hook_env, tmp_path):
    del hook_env["ARKKVM_CERT_UPDATER_ENV"]
    hook_env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
    path = tmp_path / "xdg" / "arkkvm-cert-updater" / "config.env"
    path.parent.mkdir(parents=True)
    path.write_text("ARKKVM_CERT_NAME=kvm.example.com\n")
    _, calls = run_hook(hook_env)
    assert calls[0]["argv"][2] == str(path)


def test_relative_xdg_config_home_ignored(hook_env, tmp_path):
    del hook_env["ARKKVM_CERT_UPDATER_ENV"]
    hook_env["XDG_CONFIG_HOME"] = "relative"
    path = _user_config(tmp_path / "home", "ARKKVM_CERT_NAME=kvm.example.com\n")
    _, calls = run_hook(hook_env)
    assert calls[0]["argv"][2] == str(path)


def test_finds_updater_in_home_local_bin(hook_env, tmp_path):
    local_bin = tmp_path / "home" / ".local" / "bin"
    local_bin.mkdir(parents=True)
    (tmp_path / "bin" / "arkkvm-cert-updater").rename(local_bin / "arkkvm-cert-updater")
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert [c["prog"] for c in calls] == ["updater"]


def test_reapply_defaults_to_certbot_dir_in_home(hook_env, tmp_path):
    # No root branch: the default is under the user's config dir, whoever runs the hook.
    del hook_env["RENEWED_LINEAGE"]
    lineage = tmp_path / "home" / ".config" / "letsencrypt" / "live" / "kvm.example.com"
    lineage.mkdir(parents=True)
    config(hook_env, "")
    result, calls = run_hook(hook_env, "--reapply")
    assert result.returncode == 0, result.stderr
    assert calls[0]["env"]["RENEWED_LINEAGE"] == str(lineage)


def test_reapply_default_ignores_xdg_config_home(hook_env, tmp_path):
    # Like config.py and the spec: certbot's live folder is $HOME/.config/letsencrypt/live, wherever
    # XDG_CONFIG_HOME points.
    del hook_env["RENEWED_LINEAGE"]
    hook_env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
    (tmp_path / "xdg" / "letsencrypt" / "live" / "kvm.example.com").mkdir(parents=True)
    lineage = tmp_path / "home" / ".config" / "letsencrypt" / "live" / "kvm.example.com"
    lineage.mkdir(parents=True)
    config(hook_env, "")
    result, calls = run_hook(hook_env, "--reapply")
    assert result.returncode == 0, result.stderr
    assert calls[0]["env"]["RENEWED_LINEAGE"] == str(lineage)


def test_reapply_missing_dir_suggests_setting(hook_env):
    del hook_env["RENEWED_LINEAGE"]
    config(hook_env, "ARKKVM_CERT_NAME=nothing-here\n")
    result, _ = run_hook(hook_env, "--reapply")
    assert result.returncode == 1 and "ARKKVM_LETSENCRYPT_LIVE" in result.stderr


def test_empty_token_in_environment_overrides_config(hook_env):
    # An explicitly empty variable in the environment wins over config.env, as it does for the updater:
    # here it turns Proton Pass off for one run, using a plaintext password from the environment.
    config(hook_env, "ARKKVM_PASSWORD=pass://Infra/Item/password\nPROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_cfg::KEY\n")
    env = {**hook_env, "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "", "ARKKVM_PASSWORD": "plain"}
    result, calls = run_hook(env)
    assert result.returncode == 0, result.stderr
    assert [c["prog"] for c in calls] == ["updater"]


def test_empty_cert_name_in_environment_overrides_config(hook_env):
    config(hook_env, "")  # config.env sets the certificate name
    result, calls = run_hook({**hook_env, "ARKKVM_CERT_NAME": ""})
    assert result.returncode != 0
    assert "ARKKVM_CERT_NAME is not set" in result.stderr
    assert calls == []


# The updater only sees the hook's private, token-free copy of config.env, so the hook
# itself must warn about the original files that hold the Proton Pass token.


def _pp_config(hook_env, mode: int) -> Path:
    path = Path(hook_env["ARKKVM_CERT_UPDATER_ENV"])
    path.write_text("ARKKVM_CERT_NAME=kvm.example.com\nPROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_cfg::KEY\n")
    path.chmod(mode)
    return path


def test_hook_warns_about_readable_original_config(hook_env):
    path = _pp_config(hook_env, 0o644)
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert f"arkkvm-deploy-hook: warning: {path} is accessible by other users" in result.stderr
    assert f"chmod 600 {path}" in result.stderr
    assert "pst_cfg" not in result.stderr
    assert [c["prog"] for c in calls][-1] == "pass-cli"  # still runs: a warning, not an error


def test_hook_quiet_about_private_original_config(hook_env):
    _pp_config(hook_env, 0o600)
    result, _ = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert "warning" not in result.stderr


def test_hook_warns_about_readable_token_file(hook_env, tmp_path):
    config_path = _pp_config(hook_env, 0o600)
    config_path.write_text("ARKKVM_CERT_NAME=kvm.example.com\n")
    token = tmp_path / "token"
    token.chmod(0o640)
    result, _ = run_hook({**hook_env, "ARKKVM_PASS_TOKEN_FILE": str(token)})
    assert result.returncode == 0, result.stderr
    assert f"{token} is accessible by other users" in result.stderr
    assert str(config_path) not in result.stderr


def test_hook_warns_about_original_config_owned_by_someone_else(hook_env, tmp_path):
    _pp_config(hook_env, 0o600)
    # Make the file look owned by uid 4242, whoever runs the tests: root-owned files are accepted on purpose,
    # and CI runners often run as root, so faking the current user instead would not work there.
    fake_ls = Path(hook_env["PATH"].split(":")[0]) / "ls"
    fake_ls.write_text("#!/bin/sh\n/bin/ls \"$@\" | awk '{$3 = 4242; print}'\n")
    fake_ls.chmod(0o755)
    result, _ = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert "is owned by another user (uid 4242)" in result.stderr


def test_hook_leaves_permission_warnings_to_the_updater_without_proton_pass(hook_env):
    path = Path(hook_env["ARKKVM_CERT_UPDATER_ENV"])
    path.write_text("ARKKVM_CERT_NAME=kvm.example.com\n")
    path.chmod(0o644)
    result, calls = run_hook(hook_env)
    assert result.returncode == 0, result.stderr
    assert [c["prog"] for c in calls] == ["updater"]
    assert "warning" not in result.stderr  # the updater reads this very file and warns itself
