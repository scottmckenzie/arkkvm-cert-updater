#!/bin/sh
set -eu

. $HOME/.letsencrypt/arkkvm.env
export ARKKVM_PASSWORD

: "${ARKKVM_PASSWORD:?ARKKVM_PASSWORD is not configured}"
: "${RENEWED_DOMAINS:?RENEWED_DOMAINS was not supplied by Certbot}"
: "${RENEWED_LINEAGE:?RENEWED_LINEAGE was not supplied by Certbot}"

$HOME/arkkvm-cert-updater/.venv/bin/python \
  $HOME/arkkvm-cert-updater/arkkvm_update_cert.py \
  "$RENEWED_DOMAINS" \
  --cert "$RENEWED_LINEAGE/fullchain.pem" \
  --key "$RENEWED_LINEAGE/privkey.pem" \
  --reboot
