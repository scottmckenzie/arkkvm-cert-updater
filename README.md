# ArkKVM certificate updater

`arkkvm_update_cert.py` uses the same device interface as the ArkKVM browser UI:
it authenticates locally, establishes a WebRTC session, and sends
`setTLSState` over the `rpc` data channel.

## Install

Requires [uv](https://docs.astral.sh/uv/). Python 3.14 or newer is required;
uv will download a suitable interpreter if needed.

Clone the repository and install the command with:

```sh
uv tool install .
```

This places the `arkkvm_update_cert` executable in uv's tool bin directory
(typically `~/.local/bin`). If that directory is not already on your `PATH`,
run `uv tool update-shell` to add it.

After pulling updates from the repository, reinstall the tool to get the latest
version:

```sh
uv tool install --reinstall .
```

## Apply a custom certificate

```sh
arkkvm_update_cert http://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --reboot
```

The password is prompted without echo. For unattended use, specify it through
the `ARKKVM_PASSWORD` environment variable:

```sh
export ARKKVM_PASSWORD='your-device-password'
arkkvm_update_cert http://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --reboot
```

An explicit `--password` takes precedence over `ARKKVM_PASSWORD`, but may expose
the password in shell history and process listings. With neither source set,
the script displays the hidden prompt.

If the device is currently using an untrusted/self-signed HTTPS certificate:

```sh
arkkvm_update_cert https://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --insecure \
  --reboot
```

Use `--ca-file device-ca.pem` instead of `--insecure` when its issuing CA is
available. If local authentication is disabled, use `--no-password`.

## Other TLS modes

```sh
arkkvm_update_cert http://arkkvm.local --mode self-signed --reboot
arkkvm_update_cert https://arkkvm.local --mode disabled --insecure --reboot
```

Without `--reboot`, the script persists and verifies the setting but leaves the
reboot to you. Keep an HTTP route or physical access available when testing a
new certificate so a bad hostname/trust configuration does not lock you out.

## Certbot deploy hook

This assumes your certbot --config-dir is set to $HOME/.letsencrypt

```sh
git clone https://github.com/scottmckenzie/arkkvm-cert-updater.git
cd arkkvm-cert-updater
uv tool install .
certbot certonly --config-dir $HOME/.letsencrypt --deploy-hook $PWD/certbot-deploy-hook.sh -d arkkvm.example.com
```

### Daily renewal with cron

Run `crontab -e` and add this line to renew once a day. Certbot stores the
deploy hook in the renewal config, so renewals rerun it. Cron runs with a
minimal `PATH`, so certbot is called by absolute path; change it if
`command -v certbot` prints something other than `/usr/bin/certbot`.

```
# Renew Let's Encrypt certificates once a day at 03:17
17 3 * * * /usr/bin/certbot renew --quiet --config-dir $HOME/.letsencrypt --work-dir $HOME/.letsencrypt/work --logs-dir $HOME/.letsencrypt/logs
```

Pick a different minute from 17 if you like; avoid minute 0 so the request
doesn't land at the same moment as everyone else's.
