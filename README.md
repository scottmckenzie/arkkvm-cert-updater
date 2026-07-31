# ArkKVM certificate updater

`arkkvm_update_cert.py` uses the same device interface as the ArkKVM browser UI:
it authenticates locally, establishes a WebRTC session, and sends
`setTLSState` over the `rpc` data channel.

## Install

Python 3.10 or newer is recommended.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Apply a custom certificate

```sh
python3 arkkvm_update_cert.py http://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --reboot
```

The password is prompted without echo. For unattended use, specify it through
the `ARKKVM_PASSWORD` environment variable:

```sh
export ARKKVM_PASSWORD='your-device-password'
python3 arkkvm_update_cert.py http://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --reboot
```

An explicit `--password` takes precedence over `ARKKVM_PASSWORD`, but may expose
the password in shell history and process listings. With neither source set,
the script displays the hidden prompt.

If the device is currently using an untrusted/self-signed HTTPS certificate:

```sh
python3 arkkvm_update_cert.py https://arkkvm.local \
  --cert fullchain.pem \
  --key privkey.pem \
  --insecure \
  --reboot
```

Use `--ca-file device-ca.pem` instead of `--insecure` when its issuing CA is
available. If local authentication is disabled, use `--no-password`.

## Other TLS modes

```sh
python3 arkkvm_update_cert.py http://arkkvm.local --mode self-signed --reboot
python3 arkkvm_update_cert.py https://arkkvm.local --mode disabled --insecure --reboot
```

Without `--reboot`, the script persists and verifies the setting but leaves the
reboot to you. Keep an HTTP route or physical access available when testing a
new certificate so a bad hostname/trust configuration does not lock you out.

## Certbot deploy hook

This assumes your certbot --config-dir is set to $HOME/.letsencrypt

```sh
git clone https://github.com/scottmckenzie/arkkvm-cert-updater.git
cd arkkvm-cert-updater
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
certbot certonly --config-dir $HOME/.letsencrypt --deploy-hook $PWD/certbot-deploy-hook.sh -d arkkvm.example.com
```
