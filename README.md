# arkkvm-cert-updater

Install a [Let's Encrypt](https://letsencrypt.org/) certificate on an ArkKVM device (a KVM-over-IP device with a local web UI) and keep it current, with a deploy hook for [certbot](https://certbot.eff.org/). The new certificate only takes effect after a reboot, so **every install reboots the ArkKVM**; the reboot takes well under 5 minutes. When the right certificate is already served, the device is not touched.

Only the ArkKVM's local web UI is supported. The device speaks its own web API: local login, then WebRTC with an rpc data channel.

## How it works

1. Loads the certbot lineage (`fullchain.pem`, `privkey.pem`, `chain.pem`) and checks that the key matches the certificate. Before contacting the device (even with `--check`), it also checks that the certificate is currently valid and covers the host name or IP address in `ARKKVM_URL` (exit 3 if not), so a certificate that could never verify is not installed and the device is not rebooted for nothing.
2. Fetches the certificate the device is serving now (TLS handshake, no login) and chooses trust (verified normally, or pinned by `ARKKVM_TLS_FINGERPRINT`). If the served certificate equals the lineage's leaf and verifies normally, it logs "already installed" and exits 0 without logging in, unless `--force`. With `--check`, it logs in to confirm the password works, compares, and changes nothing.
3. Logs in with the local password, opens the WebRTC session, sets the TLS state to custom with the certificate and key, and confirms the device reports mode custom.
4. Reboots the device (a dropped connection during the reboot is expected).
5. Polls the TLS handshake every 10 seconds, up to `ARKKVM_RESET_TIMEOUT` (default 300), until the device presents the new certificate, it passes normal verification for the host name, and the fingerprint matches. Anything else is a failure, and the message says what the device is serving instead. With `--force`, when the device already served this certificate, the first poll can match before the device has finished rebooting, so success may be reported early. That is harmless: the device comes back with the same certificate.

The web API is undocumented and may change between firmware versions. Errors include an excerpt of the response, never the password or cookies.

### The device's identity is always verified

The password and session cookie are only sent to a server whose identity has been checked. TLS verification is never turned off, and redirects from the device are never followed (a redirect is reported as an error), so the password, key and session never go to another address. Each connection that carries credentials is either:

- **Verified normally**: system CAs (or, instead of them, `ARKKVM_CA_BUNDLE`), with host name checking against `ARKKVM_URL`. The intermediates in the lineage's `chain.pem` are also offered when building the chain, because many device web servers send only the leaf certificate. Before an install, the intermediates from every earlier `chainN.pem` certbot kept in `archive/<name>/` are offered too: Let's Encrypt rotates its intermediates, so the certificate still on the device may need a different one than the renewal. They only help build a chain; it must still end at a trusted root.
- **Pinned**: if normal verification fails and `ARKKVM_TLS_FINGERPRINT` is set, the server is accepted only if its certificate has exactly that SHA-256 fingerprint. This is for the first install, while the device still has its self-signed certificate. The pin is checked on every such connection, for the login request and the signalling websocket alike.

If neither passes, the tool stops before sending anything (exit 4). The password has no command-line option: it only comes from the env file or the environment.

## Install

Run everything as the same ordinary user that runs certbot. Root is not supported.

```sh
uv tool install .            # from a checkout of this repository
install -m 755 certbot/arkkvm-deploy-hook.sh ~/.local/bin/arkkvm-deploy-hook
```

`uv tool install` puts `arkkvm-cert-updater` in `~/.local/bin`. certbot should run the hook script, not the updater directly: the script finds the updater even when certbot's `PATH` doesn't include `~/.local/bin`, and it resolves Proton Pass references.

### Configuration file

The tool and the hook use the first of these that exists:

1. The file named by `--env-file` (updater only), or by the `ARKKVM_CERT_UPDATER_ENV` environment variable
2. `${XDG_CONFIG_HOME:-~/.config}/arkkvm-cert-updater/config.env`

There is no `/etc` fallback. The file holds secrets, so keep it private:

```sh
install -d -m 700 ~/.config/arkkvm-cert-updater
install -m 600 certbot/config.env.example ~/.config/arkkvm-cert-updater/config.env
$EDITOR ~/.config/arkkvm-cert-updater/config.env
```

The tool warns if the group or others have any access to the file (mode `go+rwx`, so use `600`), or if someone other than you or root owns it. Use absolute paths in it: `~` and `$HOME` are not expanded. The format is `KEY=VALUE`, with optional `export`, quotes and `#` comments. The real environment overrides the file.

| Setting | Meaning | Default |
|---|---|---|
| `ARKKVM_URL` | `https://host[:port]`, e.g. `https://kvm.example.com`; `http://` is rejected | required |
| `ARKKVM_PASSWORD` | device password, normally a `pass://` reference | required |
| `ARKKVM_CERT_NAME` | certbot certificate name; other lineages are skipped | required |
| `ARKKVM_TLS_FINGERPRINT` | SHA-256 pin for the first install | unset |
| `ARKKVM_CA_BUNDLE` | CA file used instead of the system CAs | system CAs |
| `ARKKVM_RESET_TIMEOUT` | seconds to wait after the reboot | 300 |
| `ARKKVM_TIMEOUT` | per-step timeout in seconds for HTTP, signalling, ICE and RPC | 20 |
| `ARKKVM_LETSENCRYPT_LIVE` | certbot `live` folder, for `--reapply` | `~/.config/letsencrypt/live` |
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | Proton Pass agent token; enables Proton Pass | unset |
| `PROTON_PASS_AGENT_REASON` | audit-log reason (max 300 characters) | names the certificate |
| `ARKKVM_PASS_TOKEN_FILE` | token in its own file (mode 600) instead | unset |
| `ARKKVM_PASS_CLI`, `ARKKVM_UPDATER_BIN` | program paths for the hook | `PATH`, then `~/.local/bin` |

### Command-line options

Run the updater through the hook (`arkkvm-deploy-hook --reapply [--check] [--force]`): the hook forwards extra arguments to the updater. **The updater does not resolve `pass://` references; only the hook does, through `pass-cli run`.** Running `arkkvm-cert-updater` directly works only when `ARKKVM_PASSWORD` is the plaintext password. With Proton Pass, always go through the hook, with the token configured. The updater refuses an `ARKKVM_PASSWORD` that is still an unresolved `pass://...` reference (exit 2), so it never sends it to the device.

```
arkkvm-cert-updater [--env-file FILE] [--certbot] [--lineage DIR] [--check] [--force] [-v]
```

| Option | Meaning |
|---|---|
| `--env-file FILE` | read settings from this file |
| `--certbot` | run as a certbot deploy hook: use `$RENEWED_LINEAGE`, skip other certificates |
| `--lineage DIR` | certbot lineage folder (default: `ARKKVM_LETSENCRYPT_LIVE/ARKKVM_CERT_NAME`) |
| `--check` | log in, read and compare the certificates, change nothing |
| `--force` | install even if the device already serves this certificate |
| `-v`, `--verbose` | debug logging and tracebacks |

### Check the network path

The machine running the tool must resolve the device's name and reach its HTTPS port:

```sh
getent hosts kvm.example.com
curl -skI --max-time 10 https://kvm.example.com/ | head -n 1
```

Test by name, as the tool connects to the host in `ARKKVM_URL`. Any HTTP response means the path works (`-k` is acceptable here only because no credentials are sent).

## Issue the certificate with certbot

certbot's default key type works. The lineage needs `fullchain.pem`, `privkey.pem` and `chain.pem`, and the key must match the certificate.

certbot can run as an ordinary user if it has folders it can write to. Put them in `~/.config/letsencrypt/cli.ini`, which certbot reads automatically (absolute paths, since certbot doesn't expand `~`):

```ini
config-dir = /home/you/.config/letsencrypt
work-dir = /home/you/.local/state/letsencrypt
logs-dir = /home/you/.local/state/letsencrypt/log
```

Issue the certificate, with your own DNS-01 options, attaching the hook to this certificate only:

```sh
certbot certonly --cert-name kvm.example.com -d kvm.example.com \
    <your DNS-01 options> \
    --deploy-hook /home/<user>/.local/bin/arkkvm-deploy-hook
```

certbot saves the hook in that certificate's renewal config (`renew_hook`), so only its renewals run it. The hook also runs once on this first issue, which would be the first install: finish `config.env` first (see [First install on a new device](#first-install-on-a-new-device)), or leave `--deploy-hook` off, follow First install, and add the hook afterwards.

**Attach the hook per certificate (`--deploy-hook`, or `renew_hook` in the renewal config), never in `renewal-hooks/deploy/`.** A hook in that folder runs for every certificate you renew. This hook skips lineages that aren't `ARKKVM_CERT_NAME`, but that is only a guard.

For a certificate that already exists, either re-run `certonly` with `--deploy-hook`, or add this under `[renewalparams]` in `renewal/kvm.example.com.conf` in certbot's config folder:

```ini
renew_hook = /home/<user>/.local/bin/arkkvm-deploy-hook
```

## First install on a new device

A fresh device serves plain HTTP only; HTTPS is off until a certificate is enabled. A device that already serves a verifying certificate over HTTPS needs no pin: skip to step 3. The certificate must already be issued, as `--check` and `--reapply` read it from `ARKKVM_LETSENCRYPT_LIVE/ARKKVM_CERT_NAME`.

1. In the ArkKVM web UI, enable the self-signed TLS certificate and reboot the device.
2. In a browser, open the device and read the certificate's SHA-256 fingerprint in the certificate viewer. Set `ARKKVM_TLS_FINGERPRINT` in `config.env` (this is a placeholder: use the one your browser shows):

   ```sh
   ARKKVM_TLS_FINGERPRINT=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
   ```

3. Check the settings and the login first, which changes nothing, then install:

   ```sh
   ~/.local/bin/arkkvm-deploy-hook --reapply --check
   ~/.local/bin/arkkvm-deploy-hook --reapply
   ```

   The device reboots, which takes a few minutes, and the tool waits for it to come back with the new certificate. Exit 6 means the device refused the certificate.
4. Remove the `ARKKVM_TLS_FINGERPRINT` line from `config.env`. The device now serves a Let's Encrypt certificate, which verifies normally.

## Schedule the weekly re-apply

certbot runs a deploy hook once, right after a renewal, and never retries it. If the device or Proton Pass is unreachable at that moment, the new certificate isn't installed. A weekly `--reapply` installs the current certificate if the device isn't already serving it, and does nothing otherwise (no reboot).

This project uses cron, not systemd timers. Add a line next to your `certbot renew` entry (`crontab -e`). The time is an example:

```cron
17 3 * * * /usr/bin/certbot renew --quiet
# Re-apply the ArkKVM certificate weekly if it isn't installed (no-op otherwise)
41 4 * * 0 /home/<user>/.local/bin/arkkvm-deploy-hook --reapply >> /home/<user>/.local/state/arkkvm-cert-updater.log 2>&1
```

Cron runs with a minimal environment, so:

- Use absolute paths. `PATH` is usually just `/usr/bin:/bin`. The hook still finds `arkkvm-cert-updater` and `pass-cli` in `~/.local/bin`; otherwise set `ARKKVM_UPDATER_BIN` and `ARKKVM_PASS_CLI`.
- `XDG_*` variables are not set. The hook falls back to `~/.config` and `~/.config/letsencrypt/live`. If your certbot `config-dir` is elsewhere, set `ARKKVM_LETSENCRYPT_LIVE`.
- Output goes to cron mail unless redirected. The line above appends it to a log file; create its folder first (`mkdir -p ~/.local/state`).
- Keep secrets off the crontab line. They stay in `config.env` or Proton Pass.

## Secrets in Proton Pass

The deploy hook can fetch secrets from Proton Pass with [`pass-cli`](https://protonpass.github.io/pass-cli) 2.7.0 or later (installed in `~/.local/bin`). Keep the device password in a Proton Pass item and put a `pass://vault/item/field` reference in `config.env` as `ARKKVM_PASSWORD`.

The recommended setup is a Proton Pass **agent**: a token limited to the vaults you choose, whose every read is recorded with a reason in an audit log. Create one that can read only the vault holding this secret:

```sh
pass-cli agent create arkkvm-cert-updater --expiration 1y --vault Infra
```

It prints a line `PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_...`. Paste that line into `config.env` (mode 600), next to the reference:

```sh
ARKKVM_PASSWORD="pass://Infra/ArkKVM/password"

PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_xxxx...xxxx::TOKENKEY
PROTON_PASS_AGENT_REASON="Install the renewed TLS certificate on the ArkKVM"
```

`PROTON_PASS_AGENT_REASON` is optional (up to 300 characters). Without it, the hook uses a reason that names the certificate. See what the agent read, and why, with `pass-cli agent monitor arkkvm-cert-updater`. A plain personal access token (`pass-cli personal-access-token create`) works too and ignores the reason. To keep the token out of `config.env`, put it in its own file (mode 600) and set `ARKKVM_PASS_TOKEN_FILE=/home/you/.config/arkkvm-cert-updater/pass-token`. The file can hold the token alone or the whole line `agent create` prints.

On each run, the hook logs in with the token, runs the updater under `pass-cli run`, which resolves the references, and logs out again.

- **Your own pass-cli login is never touched.** The hook uses a private throwaway session folder (`PROTON_PASS_SESSION_DIR`, with `PROTON_PASS_KEY_PROVIDER=fs`) and deletes it afterwards, even on failure.
- **The token only reaches `pass-cli login`**, through the environment and never the command line. `pass-cli run` and the updater get a copy of `config.env` without the token line.
- **One secret stays on disk**: the token. It is limited to one vault, expires, and can be revoked from Proton Pass.

**The agent token expires** (after a year with `--expiration 1y`). Before it does, extend it with `pass-cli agent renew`, or create a new one and replace the token line in `config.env` (or `ARKKVM_PASS_TOKEN_FILE`). Once it has expired, `pass-cli login` fails, and every renewal hook and weekly re-apply fails with exit 1. Put the expiry date in your calendar.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK: installed, already installed, check passed, or not the ArkKVM's certificate |
| 1 | the hook couldn't start the updater (missing `config.env`, updater or `pass-cli`, or `pass-cli login` failed, e.g. an expired token), or an unexpected error |
| 2 | configuration error (including an unresolved `pass://` password) |
| 3 | certificate (lineage) error: unreadable, key mismatch |
| 4 | device identity failure (TLS verification and pin both failed) |
| 5 | login failed (401/403 from the local login) |
| 6 | refused: the device rejected the certificate, or reported a different TLS state afterwards; the old certificate stays and no reboot happens |
| 7 | verification after the reboot failed or timed out |
| 8 | other device/protocol error, or network failure |

## Things only a real run will tell

- The exit-5 mapping (401/403 from the local login) is assumed and gets confirmed by the first real run.
- Whether the KVM's HTTPS listener serves the full chain correctly after the reboot is assumed, not confirmed.
- Whether `ARKKVM_RESET_TIMEOUT` (300 s) is always enough for the device to come back with the new certificate is unconfirmed.
- The device's web API is undocumented and may change between firmware versions, so errors include an excerpt of the response, never the password or cookies.

## Development

```sh
uv sync
uv run pytest
uv run coverage run -m pytest && uv run coverage report
uv run ruff check . && uv run ruff format --check .
uv run pyrefly check
uvx --from shellcheck-py==0.11.0.1 shellcheck certbot/*.sh
uv run arkkvm-cert-updater --help
```

Tests use local fakes only (no real device).
