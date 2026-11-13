# ArkKVM supermicro-layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure `arkkvm-cert-updater` into supermicro-bmc-cert-updater's package layout, config, deploy hook (with Proton Pass) and CI, keeping the existing WebRTC device protocol.

**Architecture:** `src/arkkvm_cert_updater/` with `config.py` (env file → `Config`), `certs.py` (lineage → `Lineage`), `tls.py` (verified-or-pinned trust, served-cert probes), `device.py` (the existing async login/WebRTC/RPC code, now taking a `Trust`), `updater.py` (sync `run()` orchestration: already-installed check, install, reboot, wait), `cli.py` (argparse, exit codes). `certbot/arkkvm-deploy-hook.sh` is supermicro's hook renamed.

**Tech Stack:** Python, aiohttp, aiortc, cryptography, uv/uv_build, pytest, coverage, ruff, pyrefly, ShellCheck.

**Spec:** `docs/superpowers/specs/2026-11-13-supermicro-layout-design.md`

**Template:** `/home/claude/workspace/supermicro-bmc-cert-updater` (abbreviated **SM** below). "Copy from SM" means copy the file and rename `supermicro_bmc_cert_updater`→`arkkvm_cert_updater`, `supermicro-bmc-cert-updater`→`arkkvm-cert-updater`, `SUPERMICRO_BMC_CERT_UPDATER_ENV`→`ARKKVM_CERT_UPDATER_ENV`, `BMC_`→`ARKKVM_`, "BMC"→"KVM"/"device" in prose, then apply the listed differences. Do mechanical renames with `sed`, not by hand.

## Global Constraints

- Package `arkkvm_cert_updater`; command `arkkvm-cert-updater` = `arkkvm_cert_updater.cli:main_exit`; build backend `uv_build>=0.13.0,<0.14.0`.
- `requires-python` as low as aiortc allows, target `>=3.12`; `.python-version` = that floor; CI matrix from the floor to 3.14.
- Env file var `ARKKVM_CERT_UPDATER_ENV`; default `~/.config/arkkvm-cert-updater/config.env`; no `/etc` fallback; root unsupported.
- Keys: `ARKKVM_URL` (https only), `ARKKVM_PASSWORD` (required, `pass://` unresolved → config error, never echoed), `ARKKVM_CERT_NAME` (required), `ARKKVM_TLS_FINGERPRINT`, `ARKKVM_CA_BUNDLE`, `ARKKVM_RESET_TIMEOUT` (default 300), `ARKKVM_TIMEOUT` (default 20), `ARKKVM_LETSENCRYPT_LIVE` (default `$HOME/.config/letsencrypt/live`, absolute).
- CLI options exactly: `--env-file`, `--certbot`, `--lineage`, `--check`, `--force`, `-v/--verbose`. No password option.
- Exit codes: 0 ok, 2 config, 3 certificate, 4 identity, 5 login, 6 refused, 7 verify, 8 device/protocol/network.
- No test or step touches a real KVM, ddsmash, or the network.
- Actions pinned to full SHAs with tag comments (copy SM's `ci.yml` SHAs). Coverage `fail_under = 80`, branch coverage.
- ruff line-length 120, same lint rule set as SM; pyrefly over `src` and `tests`.
- Async tests call coroutines with `asyncio.run(...)` inside plain test functions, as the existing suite does; no pytest-asyncio.
- Conventional commits; each ends with the session's `Co-Authored-By` / `Claude-Session` trailer lines.
- **Llama delegation (owner's request):** use `mcp__llama__chat` only where output is bulky (≥ ~40 lines) and mechanical: the README draft (Task 8) and the PR description (Task 9). Validate its output by script/grep, not by re-reading it all; report bad output to the owner rather than silently rewriting it.

## Review Focus

1. **Password with `#`, quotes or `=`** in `config.env` must survive parsing intact (owner's password manager output). → Task 2 test `test_password_with_special_characters`.
2. **`ARKKVM_URL` with a trailing slash** (`https://kvm.example.com/`) must work and give `wss://kvm.example.com/webrtc/signaling/client` (no `//`). → Task 2 and Task 5 tests.
3. **Device unreachable on the weekly re-apply** (KVM powered off): exit 8 with one error line, no traceback. → Task 7 test `test_unreachable_device_exits_8`.
4. **Channel drops before the reboot RPC replies**: still proceed to waiting, and succeed if the new cert appears. → Task 5 test `test_reboot_without_reply_is_ok`, Task 6 test `test_install_then_wait`.
5. **EC (or RSA 4096) Let's Encrypt keys** must be accepted; arkkvm, unlike the BMC, has no key-type restriction. → Task 3 test `test_accepts_ec_and_rsa_keys`.

---

### Task 1: Package scaffold and tooling

**Files:**
- Modify: `pyproject.toml`, `.gitignore`, `uv.lock`
- Create: `.python-version`, `src/arkkvm_cert_updater/__init__.py`, `tests/conftest.py`

**Interfaces:**
- Produces: importable package `arkkvm_cert_updater`; `tests/conftest.py` fixtures copied from SM's (test PKI, `make_key`, `pem`, `der`, `key_to_pem`, lineage builders) with `KEY_TYPES` unchanged.

- [ ] **Step 1: Find the Python floor.** In a scratch dir, `uv init --python 3.12 && uv add aiohttp aiortc cryptography`; repeat with 3.13 if 3.12 fails. The lowest that resolves and imports `aiortc` is the floor.
- [ ] **Step 2: Rewrite `pyproject.toml`** from SM's: name `arkkvm-cert-updater`, description "Install Let's Encrypt certificates on ArkKVM devices, with a certbot deploy hook", dependencies `aiohttp`, `aiortc`, `cryptography` (keep current lower bounds), script per Global Constraints, SM's dev group minus `responses`/`types-requests`, SM's `[tool.*]` sections with `source = ["arkkvm_cert_updater"]`. Copy SM's `.gitignore`. Write `.python-version`.
- [ ] **Step 3: Create** `src/arkkvm_cert_updater/__init__.py` (docstring "Install Let's Encrypt certificates on ArkKVM devices.") and copy `tests/conftest.py` from SM.
- [ ] **Step 4: Keep the old suite running** during the move: in `pyproject.toml` add `pythonpath = ["."]` under `[tool.pytest.ini_options]` temporarily so `import arkkvm_update_cert` still works (removed in Task 7).
- [ ] **Step 5: Verify.** `uv lock && uv sync && uv run pytest -q` → all existing tests pass; `uv run python -c "import arkkvm_cert_updater"` → no error.
- [ ] **Step 6: Commit** `build: switch to uv_build src layout and supermicro tooling`.

### Task 2: config.py

**Files:**
- Create: `src/arkkvm_cert_updater/config.py`, `tests/test_config.py`

**Interfaces:**
- Produces: `APP_NAME = "arkkvm-cert-updater"`, `ENV_FILE_VAR = "ARKKVM_CERT_UPDATER_ENV"`, `ConfigError`, `parse_env_file(path) -> dict[str,str]`, `user_config_dir(environ) -> Path`, `find_env_file(environ) -> Path | None`, `load_env(env_file, environ) -> dict[str,str]`, `resolve_config(env) -> Config`, and

```python
@dataclass(frozen=True)
class Config:
    url: str  # normalised: "https://host[:port]", no trailing slash
    host: str
    port: int
    password: str
    cert_name: str
    tls_fingerprint: bytes | None
    ca_bundle: Path | None
    reset_timeout: float
    timeout: float
    live_dir: Path
```

- [ ] **Step 1: Copy SM's `tests/test_config.py`**, rename, delete username tests, and add:

```python
def test_url_must_be_https(): ...           # ARKKVM_URL=http://kvm → ConfigError matching "https://"
def test_url_trailing_slash_normalised():   # "https://kvm.example.com/" → cfg.url == "https://kvm.example.com", port 443
def test_timeout_default_and_custom():      # unset → 20.0; "5" → 5.0; "0", "-1", "nan", "x" → ConfigError naming ARKKVM_TIMEOUT
def test_password_with_special_characters(tmp_path):
    # file line: ARKKVM_PASSWORD='p#ss="x"=y'  → cfg.password == 'p#ss="x"=y'
def test_unresolved_pass_reference_not_echoed():
    # ARKKVM_PASSWORD=pass://Vault/Item/password → ConfigError; "Vault" not in str(err)
```

- [ ] **Step 2: Run** `uv run pytest tests/test_config.py -q` → FAIL (module missing).
- [ ] **Step 3: Copy SM's `config.py`**, rename, remove `username`, add `timeout` (`ARKKVM_TIMEOUT`, default `20.0`, same validation as `_parse_timeout`, error names the key), and set `url` to `f"https://{netloc}"` with no trailing slash.
- [ ] **Step 4: Run** `uv run pytest tests/test_config.py -q` → PASS.
- [ ] **Step 5: Commit** `feat: add config module (config.env, ARKKVM_* settings)`.

### Task 3: certs.py

**Files:**
- Create: `src/arkkvm_cert_updater/certs.py`, `tests/test_certs.py`
- Delete: `tests/test_cert_material.py` (its cases move into `test_certs.py`)

**Interfaces:**
- Produces: `CertificateError`, `sha256_fingerprint(der) -> bytes`, `format_fingerprint(fp) -> str`, `load_lineage(path: Path) -> Lineage` with

```python
@dataclass(frozen=True)
class Lineage:
    name: str
    leaf_der: bytes
    certs_pem: str  # every CERTIFICATE block of fullchain.pem, joined with "\n", trailing "\n"
    key_pem: str  # privkey.pem stripped, trailing "\n"
    chain_pem: bytes
    fingerprint: bytes  # sha256 of leaf_der
```

(`certs_pem`/`key_pem` are `str` because `setTLSState` takes JSON strings.)

- [ ] **Step 1: Copy SM's `tests/test_certs.py`**, drop the RSA-2048 rejection tests, port each case from `tests/test_cert_material.py` (missing file, no PEM, no key, encrypted key, corrupt body, mismatch), and add:

```python
@pytest.mark.parametrize("key_type", ["ec256", "rsa2048", "rsa4096"])
def test_accepts_ec_and_rsa_keys(make_lineage, key_type):
    lin = load_lineage(make_lineage(key_type=key_type))
    assert lin.certs_pem.startswith("-----BEGIN CERTIFICATE-----") and lin.certs_pem.endswith("\n")
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Copy SM's `certs.py`**, delete the RSA-2048 checks and `REISSUE_HINT`, keep the key-matches-certificate check, return `str` PEM fields as above.
- [ ] **Step 4: Run** `uv run pytest tests/test_certs.py -q` → PASS.
- [ ] **Step 5: Commit** `feat: add certbot lineage loader`.

### Task 4: tls.py

**Files:**
- Create: `src/arkkvm_cert_updater/tls.py`, `tests/test_tls.py`, `tests/tls_server.py`

**Interfaces:**
- Consumes: `certs.sha256_fingerprint`, `certs.format_fingerprint`.
- Produces: `IdentityError`, `fetch_served_certificate(host, port, *, timeout) -> bytes`, `verification_context(chain_pem, ca_bundle) -> ssl.SSLContext`, `is_verified(host, port, context, *, timeout) -> bool`, `Trust(context, pin)` (frozen, pin is 32 bytes or None), `choose_trust(host, port, *, context, pin, timeout) -> Trust`, and

```python
def aiohttp_ssl(trust: Trust) -> ssl.SSLContext | aiohttp.Fingerprint:
    """Verified → trust.context; pinned → aiohttp.Fingerprint(trust.pin)."""
```

- [ ] **Step 1: Copy SM's `tests/tls_server.py`** and the parts of `tests/test_tls.py` that cover the five functions above (drop `make_session`/adapter tests). Error text must say `ARKKVM_TLS_FINGERPRINT`. Add:

```python
def test_aiohttp_ssl_verified_returns_context(): assert aiohttp_ssl(Trust(ctx, None)) is ctx
def test_aiohttp_ssl_pinned_returns_fingerprint():
    fp = aiohttp_ssl(Trust(ctx, b"\x01" * 32)); assert isinstance(fp, aiohttp.Fingerprint)
def test_pinned_session_rejects_other_cert(tls_server):  # local test server; wrong pin → aiohttp.ServerFingerprintMismatch
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Copy SM's `tls.py`** keeping only those five functions/classes (no requests code); add `aiohttp_ssl`.
- [ ] **Step 4: Run** `uv run pytest tests/test_tls.py -q` → PASS.
- [ ] **Step 5: Commit** `feat: add verified-or-pinned TLS trust for aiohttp`.

### Task 5: device.py (move the protocol code)

**Files:**
- Create: `src/arkkvm_cert_updater/device.py`, `tests/test_device.py`
- Delete: `tests/test_protocol.py`, `tests/test_update_device.py` (their cases move into `test_device.py`)

**Interfaces:**
- Consumes: `tls.Trust`, `tls.aiohttp_ssl`.
- Produces:

```python
class DeviceError(Exception): ...          # exit 8
class LoginError(DeviceError): ...         # exit 5: HTTP 401/403 from /auth/login-local
class RefusedError(DeviceError): ...       # exit 6: setTLSState error, or getTLSState mode != "custom"
class ProtocolError(DeviceError): ...      # exit 8: bad replies, timeouts, network (wrap aiohttp.ClientError/OSError/TimeoutError)

async def check_login(base_url: str, password: str, *, trust: Trust, timeout: float) -> None
async def install_certificate(base_url: str, password: str, certs_pem: str, key_pem: str,
                              *, trust: Trust, timeout: float) -> None   # setTLSState, verify, reboot
```

- [ ] **Step 1: Port the tests.** Move every case from `test_protocol.py` and `test_update_device.py` to `test_device.py` against the new names, keeping the fakes. Drop cases for removed features (`--mode`, no-password, `--insecure`, `normalise_base_url`). Add:

```python
def test_login_401_raises_login_error(); def test_login_403_raises_login_error()
def test_login_500_raises_protocol_error()
def test_set_tls_state_error_raises_refused(device); def test_verification_mismatch_raises_refused(device)
def test_reboot_without_reply_is_ok(device)          # reboot RPC times out/closes → returns normally
def test_signaling_url_https_only():
    assert signaling_url("https://kvm.example.com", "t") == "wss://kvm.example.com/webrtc/signaling/client?csrf-token=t"
def test_connector_uses_trust(device)                # TCPConnector got ssl=aiohttp_ssl(trust)
def test_login_does_not_follow_redirects(device)     # session.post called with allow_redirects=False
def test_client_error_wrapped_as_protocol_error(device)
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Move** `checked_json`, `login`, `rpc_call`, `signaling_url`, `add_remote_candidate`, `receive_signal`, `wait_for_signal`, `relay_ice_candidates`, `wait_for_ice_gathering` and the body of `update_device` from `arkkvm_update_cert.py` into `device.py`. `update_device` becomes `install_certificate` (always mode `custom`, always reboot); the shared session/WebRTC setup is a private helper used by both public functions. `ArkKVMError` is replaced by the hierarchy above. The `User-Agent` becomes `arkkvm-cert-updater/<version>`.
- [ ] **Step 4: Run** `uv run pytest tests/test_device.py -q` → PASS.
- [ ] **Step 5: Commit** `refactor: move the device protocol into device.py with typed errors`.

### Task 6: updater.py

**Files:**
- Create: `src/arkkvm_cert_updater/updater.py`, `tests/test_updater.py`

**Interfaces:**
- Consumes: `Config`, `Lineage`, `tls.*`, `device.check_login`, `device.install_certificate`.
- Produces: `Outcome` (`ALREADY_INSTALLED`, `INSTALLED`, `CHECKED`), `VerifyError`, `wait_for_certificate(...)` (copy SM verbatim), `Deps` dataclass with `fetch`, `verified`, `choose_trust`, `check_login`, `install`, `wait` (the two device entries are sync wrappers that `asyncio.run` the coroutines), and `run(config, lineage, *, force=False, check_only=False, deps=None) -> Outcome`.

- [ ] **Step 1: Adapt SM's `tests/test_updater.py`** to the `Deps` above (fake device calls instead of an `X11Client`). Required cases: already installed → no login, no install; `--force` installs anyway; `--check` logs in (via `check_login`) and returns `CHECKED` without installing; pin used when verification fails; `test_install_then_wait` (install returns, wait called with `expected=lineage.fingerprint`, `timeout=config.reset_timeout`); wait times out → `VerifyError` propagates; `LoginError` propagates.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement `run`** following SM's flow (check context and trust context built separately; already-installed check skipped by `--force` unless `--check`; no logout/reset branches, since `install_certificate` owns the whole session and treats a dropped reboot reply as success).
- [ ] **Step 4: Run** `uv run pytest tests/test_updater.py -q` → PASS.
- [ ] **Step 5: Commit** `feat: add install flow with already-installed check and post-reboot verify`.

### Task 7: cli.py and removal of the old script

**Files:**
- Create: `src/arkkvm_cert_updater/cli.py`, `src/arkkvm_cert_updater/__main__.py`
- Replace: `tests/test_cli.py`
- Delete: `arkkvm_update_cert.py`; the temporary `pythonpath` from Task 1.

**Interfaces:**
- Consumes: everything above.
- Produces: `build_parser()`, `main(argv=None, environ=None, *, deps=None) -> int`, `main_exit() -> None`.

- [ ] **Step 1: Adapt SM's `tests/test_cli.py`**, mapping exit codes per Global Constraints (`LoginError`→5, `RefusedError`→6, `VerifyError`→7, `ProtocolError`/`DeviceError`/`OSError`→8). Add:

```python
def test_unreachable_device_exits_8(capsys, ...):  # deps.fetch raises ConnectionRefusedError
    assert main([...], env) == 8
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err
def test_no_password_option(): with pytest.raises(SystemExit): build_parser().parse_args(["--password", "x"])
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Copy SM's `cli.py`**, adapted (description names the ArkKVM; `ARKKVM_*` keys in help). `__main__.py` calls `main_exit()`.
- [ ] **Step 4: Delete** `arkkvm_update_cert.py` and the temporary `pythonpath`; `grep -r arkkvm_update_cert src tests pyproject.toml` → no hits.
- [ ] **Step 5: Run the whole gate:** `uv run ruff check . && uv run ruff format --check . && uv run pyrefly check && uv run coverage run -m pytest -q && uv run coverage report` → all pass, coverage ≥ 80%. `uv run arkkvm-cert-updater --help` lists exactly the six options.
- [ ] **Step 6: Commit** `feat!: new arkkvm-cert-updater CLI driven by config.env`.

### Task 8: Deploy hook, config example, CI, docs

**Files:**
- Create: `certbot/arkkvm-deploy-hook.sh` (mode 755), `certbot/config.env.example`, `tests/test_deploy_hook.py`
- Modify: `.github/workflows/ci.yml`, `README.md`, `CLAUDE.md`
- Delete: `certbot-deploy-hook.sh`

- [ ] **Step 1: Copy SM's `tests/test_deploy_hook.py`** with `sed` renames (`BMC_`→`ARKKVM_`, `supermicro-bmc`→`arkkvm`, `bmc.example.com`→`kvm.example.com`, `SUPERMICRO_BMC_CERT_UPDATER_ENV`→`ARKKVM_CERT_UPDATER_ENV`, `BMC_UPDATER_BIN`→`ARKKVM_UPDATER_BIN`). Run → FAIL (no hook).
- [ ] **Step 2: Copy SM's hook** with the same `sed` renames, then fix prose ("BMC" → "ArkKVM"); default agent reason `arkkvm-cert-updater: install certificate <name> on the ArkKVM`. `chmod 755`. Run `uv run pytest tests/test_deploy_hook.py -q` → PASS; `uvx --from shellcheck-py==0.11.0.1 shellcheck certbot/*.sh` → clean.
- [ ] **Step 3: Write `certbot/config.env.example`** from SM's: drop username; `ARKKVM_URL=https://arkkvm.example.com`; `ARKKVM_TLS_FINGERPRINT` comment explains it's the self-signed cert enabled in the KVM's web UI, first install only; add commented `#ARKKVM_TIMEOUT=20`; agent create line uses `arkkvm-cert-updater`.
- [ ] **Step 4: Copy SM's `ci.yml`**; matrix from the Task 1 floor to 3.14; delete `certbot-deploy-hook.sh`.
- [ ] **Step 5: README via llama.** Send `mcp__llama__chat` SM's README plus the spec's Configuration, Run flow, First install and Exit codes sections; ask for the README rewritten for ArkKVM with SM's section structure. Validate by script: every SM `##` heading has an ArkKVM counterpart (except "The BMC account"); `grep -c 'BMC\|supermicro\|X11'` → 0; every `ARKKVM_*` key in `config.env.example` appears; every CLI option appears; no `--insecure`, `--mode`, `--reboot`, `--password`, `~/.letsencrypt/`. Fix small slips inline; if the structure is off, re-delegate with `history`. Tell the owner if llama's draft needed substantial fixes.
- [ ] **Step 6: Update `CLAUDE.md`** Layout/Commands/Gotchas for the new layout (keep Development Standards). Commands: `uv sync`, `uv run coverage run -m pytest && uv run coverage report`, `uv run arkkvm-cert-updater --help`, ShellCheck line.
- [ ] **Step 7: Full gate** as Task 7 Step 5 plus ShellCheck → pass.
- [ ] **Step 8: Commit** `feat: add certbot deploy hook with Proton Pass, CI and docs`.

### Task 9: Publish on Forgejo

- [ ] **Step 1:** `git push -u forgejo feature/supermicro-layout`.
- [ ] **Step 2: PR description via llama** from `git log main..` and `git diff --stat main`; must include the spec's **Migration on ddsmash** steps verbatim, plus the safe order: `uv tool install --reinstall` replaces the `arkkvm_update_cert` command, which breaks the old hook, so do steps 2–5 in one sitting. That is safe because certbot renews only ~30 days before expiry and the current cert has ~60 days left, so no renewal can fire mid-switch. End with the session's PR attribution footer.
- [ ] **Step 3:** Open the PR on Forgejo (`mcp__forgejo__create_pull_request`, base `main`) and wait for CI (`list_workflow_runs`) → green. Do not merge; the owner merges.
- [ ] **Step 4: Open the same PR on GitHub** (owner's request, 2026-11-13): `git push -u origin feature/supermicro-layout`, then `gh pr create --repo scottmckenzie/arkkvm-cert-updater --base main` with the same title and body, `GH_TOKEN` from Proton Pass per the session's procedure. Wait for GitHub CI → green. Do not merge.
- [ ] **Step 5:** Note for the owner: close GitHub PR #5 after merge.
