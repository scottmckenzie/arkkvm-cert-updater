# ArkKVM certificate updater: restructure to the supermicro layout

Date: 2026-11-13
Status: approved 2026-11-13

## Intent

`arkkvm-cert-updater` installs a Let's Encrypt certificate on an ArkKVM device. It is a single 429-line
script with a thin certbot hook that reads a plaintext password from `~/.letsencrypt/arkkvm.env`. The
owner has two sibling projects that do the same job for other devices, `technitium-cert-updater` and
`supermicro-bmc-cert-updater` (both on `forgejo.noizy.au/claude-workspace`). They share a layout, a config
file convention, a hardened certbot deploy hook with weekly re-apply, and secrets held in Proton Pass.

The goal is to bring arkkvm to the same layout and features, **using `supermicro-bmc-cert-updater` as
the template wherever the two siblings differ** (owner's decision). After this, the three projects should
look and operate alike, so knowing one means knowing all of them.

The device protocol (local login → WebRTC signalling over a websocket → `setTLSState` / `getTLSState` /
`reboot` RPCs on the `rpc` data channel) does not change; it already works and is tested.

## Goals

- Same project layout, packaging, tooling and CI as supermicro (details under **Project**).
- Settings in `~/.config/arkkvm-cert-updater/config.env`; secrets may be `pass://` references resolved by
  the deploy hook through a Proton Pass agent token.
- A certbot deploy hook that is a straight adaptation of supermicro's: certificate-name guard,
  `--reapply` for a weekly cron catch-up, Proton Pass in a throwaway `fs`-key session.
- Never send the device password over plain HTTP or to a device whose identity is not verified.
- The weekly re-apply is a no-op (no login, no reboot) when the device already serves the right
  certificate.
- After an install, confirm the device is actually serving the new certificate; fail loudly if not.
- The deployment on **ddsmash** keeps working throughout the switchover (see **Migration**).

## Non-goals

- Changing the WebRTC/RPC protocol code beyond what the restructure needs.
- Setting TLS modes other than custom (`self-signed`, `disabled`). The `--mode` option goes away.
- Supporting devices with local authentication turned off. A password is always required; `--no-password`
  goes away.
- Running as root, systemd units, a system-wide `/etc` config (supermicro choices).
- Backward compatibility with the old CLI or `~/.letsencrypt/arkkvm.env`. This is a clean break; the one
  deployment is migrated by hand.
- Obtaining certificates. certbot already does that on ddsmash.

## Anti-goals (would make this a failure even if it works)

- The device password sent over plain HTTP, or TLS verification turned off (the old `--insecure`).
- The password or Proton Pass token on a command line, in logs, or in cron configuration.
- Rebooting the KVM every week for no reason.
- Exiting 0 while the KVM still serves the old certificate.
- Breaking the ddsmash renewal before the new version is proven there.
- Any step that connects to ddsmash or a real KVM from the development machine. The owner deploys and
  tests on the device by hand.

## Environment and facts

- The deployment is on **ddsmash**, run by certbot as an ordinary user. certbot's config dir there is
  **`~/.config/letsencrypt`** (the owner migrated it; the current README's `~/.letsencrypt` is stale). So
  supermicro's default `ARKKVM_LETSENCRYPT_LIVE=~/.config/letsencrypt/live` fits as-is.
- The current KVM certificate expires in about 60 days (around 2027-01-12), so there's time for the
  switchover, but the old hook must stay in place until the new one is proven.
- **ArkKVM TLS behaviour (from the owner):** a fresh device serves plain HTTP only; HTTPS is disabled
  until a self-signed certificate is enabled or a custom cert + key is uploaded. A new certificate takes
  effect only after a reboot. A reboot takes well under 5 minutes.
- The ddsmash KVM already serves the Let's Encrypt certificate over HTTPS, so it needs no first-run pin.
- Proton Pass: the owner already keeps secrets in Proton Pass and uses agent tokens for the sibling
  projects. Agent tokens require `PROTON_PASS_AGENT_REASON`.

## How it works

### Configuration

`config.env` (example shipped as `certbot/config.env.example`, modelled line-by-line on supermicro's):

| Key | Required | Meaning |
|---|---|---|
| `ARKKVM_URL` | yes | `https://host[:port]`, no path, query or credentials. `http://` is rejected. |
| `ARKKVM_PASSWORD` | yes | Device password. May be `pass://vault/item/field`; an unresolved `pass://` value is a config error that never echoes the value. No command-line option. |
| `ARKKVM_CERT_NAME` | yes | certbot certificate name; the hook and updater skip any other lineage. |
| `ARKKVM_TLS_FINGERPRINT` | no | SHA-256 of the device's current (self-signed) certificate, trusted for the first install only. |
| `ARKKVM_CA_BUNDLE` | no | Extra CA file for verifying the device (default: system CAs). |
| `ARKKVM_RESET_TIMEOUT` | no | Seconds to wait after the reboot for the new certificate to be served (default 300). |
| `ARKKVM_TIMEOUT` | no | Per-step timeout in seconds for HTTP, signalling, ICE and RPC (default 20, as today). |
| `ARKKVM_LETSENCRYPT_LIVE` | no | certbot live dir (default `$HOME/.config/letsencrypt/live`; absolute path). |
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN`, `PROTON_PASS_AGENT_REASON`, `ARKKVM_PASS_TOKEN_FILE`, `ARKKVM_PASS_CLI`, `ARKKVM_UPDATER_BIN` | no | Hook-only settings, same meaning as supermicro's `BMC_*` equivalents. |

Env file lookup, parsing, permission warnings and precedence (real environment overrides the file) are
supermicro's `config.py`, with `ENV_FILE_VAR = "ARKKVM_CERT_UPDATER_ENV"`.

### Verifying the device's identity

Same two modes as supermicro's `tls.py`, decided before any credentials are sent:

- **Verified**: normal verification against system CAs (or `ARKKVM_CA_BUNDLE`), with the lineage's
  `chain.pem` offered for chain building, and hostname checking.
- **Pinned**: if verification fails and `ARKKVM_TLS_FINGERPRINT` is set, the served leaf must match it
  exactly. If neither holds, exit with the identity error and send nothing.

The HTTP client is aiohttp, not requests, so the pin is enforced with aiohttp's own mechanism (e.g.
`aiohttp.Fingerprint` on the connector) for both the login request and the signalling websocket. The
`Origin` header and cookie handling stay as they are.

### First install on a new device

Documented in the README (no code beyond the pin): in the KVM's web UI switch TLS to self-signed and
reboot; read that certificate's SHA-256 fingerprint in a browser; set `ARKKVM_TLS_FINGERPRINT`; run
`--reapply`; once the LE certificate is in place, remove the pin.

### Run flow

1. Load and validate config; load the lineage (`fullchain.pem`, `privkey.pem`, `chain.pem`); check the
   key matches the certificate (existing `load_custom_material` checks, moved to `certs.py`).
2. Fetch the certificate the device serves now and choose trust (above).
3. If the served leaf equals the lineage leaf, log "already installed" and exit 0 without logging in,
   unless `--force`. `--check` stops here in every case and reports what it would do (it may log in to
   confirm the password works, as supermicro's dry run does: builder's call).
4. Log in, open the WebRTC session, `setTLSState` with mode `custom`, certificate and key; `getTLSState`
   must report mode `custom` (as today).
5. Send `reboot` (`{"force": true}`); a dropped channel during the reboot is expected, as today.
6. Poll until the device serves the new leaf, verified normally, for up to `ARKKVM_RESET_TIMEOUT`.
   Timeout → verify error.

### CLI

Command `arkkvm-cert-updater` (renamed from `arkkvm_update_cert`), options as supermicro:
`--env-file`, `--certbot`, `--lineage`, `--check`, `--force`, `-v/--verbose`. Removed: the positional
device, `--cert`, `--key`, `--password`, `--no-password`, `--mode`, `--reboot` (always reboots after an
install), `--insecure`, `--ca-file`, `--timeout` (all now config).

### Exit codes

Supermicro's scheme: 0 ok, 2 config, 3 certificate, 4 identity, 5 login (401/403 from
`/auth/login-local`; assumed, confirm on the owner's hand test), 6 refused (device rejected
the certificate / `getTLSState` mismatch), 7 verify (new certificate not served after reboot),
8 device/protocol/network.

## Deploy hook and scheduling

`certbot/arkkvm-deploy-hook.sh`: supermicro's hook with `BMC_`/`supermicro-bmc` renamed to
`ARKKVM_`/`arkkvm`. Attached to the KVM's certificate with `--deploy-hook`; skips other lineages;
`--reapply` installs the current certificate again (a no-op if already served). Weekly re-apply via the
user's crontab, documented in the README exactly as supermicro does. This replaces the
`feature/certbot-cron` branch / GitHub PR #5, which should be closed once this merges.

The PR for this work is opened and merged on **Forgejo** (`forgejo` remote, `claude-workspace/arkkvm-cert-updater`); its CI must pass there (owner's decision, 2026-11-13).

## Project

Mirror supermicro:

- `src/arkkvm_cert_updater/` with `__init__.py`, `cli.py`, `config.py`, `certs.py`, `tls.py`,
  `updater.py`, and `device.py` holding the login/WebRTC/RPC code from today's script. Module split
  inside `device.py` is the builder's call.
- `pyproject.toml`: `uv_build`, `[project.scripts] arkkvm-cert-updater = "arkkvm_cert_updater.cli:main_exit"`,
  description/readme/authors, the same dev group (coverage, pyrefly, pytest, ruff) plus whatever test
  helpers the async code needs, and the same ruff/pytest/coverage (80%, branch)/pyrefly settings.
- `.python-version` and `requires-python`: as low as aiortc allows, aiming for supermicro's 3.12 and a
  3.12–3.14 CI matrix. If a dependency forces a higher floor, use that floor and trim the matrix.
- `.github/workflows/ci.yml`: supermicro's workflow (same pinned action SHAs), ShellCheck on
  `certbot/*.sh`. It must run on both GitHub and Forgejo.
- Tests: the existing suite moved and adapted (the fakes for WebRTC, HTTP and the device are kept), plus
  supermicro-style tests for config, certs, tls, updater, cli and the deploy hook (`test_deploy_hook.py`
  runs the shell script with fake `pass-cli` and updater binaries).
- `README.md` rewritten to supermicro's section structure: How it works, Install, Configuration file,
  Command-line options, Issue the certificate with certbot, First run, Schedule the weekly re-apply,
  Secrets in Proton Pass, Exit codes, Development.
- `CLAUDE.md` updated to the new layout and commands.
- Delete `arkkvm_update_cert.py` and `certbot-deploy-hook.sh` at the root.

## Migration on ddsmash (owner does this by hand; documented in the PR description)

1. Leave the old hook and `~/.letsencrypt/arkkvm.env` in place.
2. `uv tool install --reinstall .` (installs `arkkvm-cert-updater`; the old `arkkvm_update_cert` command
   disappears, so step 5 must follow promptly or the old hook breaks: alternatively install the new
   version from a separate checkout path: builder documents the safe order).
3. Write `~/.config/arkkvm-cert-updater/config.env` (mode 600) with `ARKKVM_PASSWORD` as a `pass://`
   reference and a Proton Pass agent token for that vault.
4. `arkkvm-deploy-hook --reapply --check`, then `arkkvm-deploy-hook --reapply --force` once to prove a
   real install and reboot.
5. Point the certificate's renewal conf `renew_hook`/deploy hook at the new script; add the weekly cron
   line; delete `~/.letsencrypt/arkkvm.env`.

## Left to the builder

- Internal module boundaries in `device.py` and how much of supermicro's code is copied versus adapted.
- Whether `--check` logs in.
- Test strategy for the aiohttp pin.
- Exact README wording.

## Open points that only a real run will settle

- Whether the KVM's HTTPS listener presents `fullchain` correctly after the reboot (assumed, as today).
- Whether 300 s is enough on every boot (owner says yes).
