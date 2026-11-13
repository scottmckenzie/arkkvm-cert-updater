#!/bin/sh
# Certbot deploy hook: install a renewed certificate on an ArkKVM.
#
# Attach it to the ArkKVM's certificate only, so certbot runs it for that certificate's renewals:
#   certbot certonly --cert-name <ARKKVM_CERT_NAME> ... --deploy-hook /path/to/arkkvm-deploy-hook
# certbot runs it once for each successful issue or renewal, with RENEWED_LINEAGE pointing at
# <certbot config dir>/live/<cert-name>. As a guard, if the lineage name is not ARKKVM_CERT_NAME the
# hook prints a notice and exits 0 without doing anything.
#
# It runs as whichever user runs certbot; root is not supported.
#
# Run it with --reapply (outside certbot, e.g. from cron) to install the current certificate for
# ARKKVM_CERT_NAME again. This catches up after a failed deploy, which certbot never retries.
#
# Settings come from the first of these that exists (see config.env.example):
#   $ARKKVM_CERT_UPDATER_ENV
#   ${XDG_CONFIG_HOME:-~/.config}/arkkvm-cert-updater/config.env
# ARKKVM_CERT_NAME is required there (or in the environment).
#
# Proton Pass: if PROTON_PASS_PERSONAL_ACCESS_TOKEN or ARKKVM_PASS_TOKEN_FILE is set, the hook logs in
# to Proton Pass with that personal access token or agent token and runs the updater under
# `pass-cli run`, so config.env values can be pass://vault/item/field references.
#
# These variables, from the environment or config.env, control the hook itself:
#   ARKKVM_CERT_UPDATER_ENV  env file (environment only; see the search order above)
#   ARKKVM_CERT_NAME                 certbot certificate name to act on (required)
#   ARKKVM_UPDATER_BIN               updater program (default: on PATH, ~/.local/bin, /usr/local/bin)
#   ARKKVM_LETSENCRYPT_LIVE          certbot live directory for --reapply
#                                 (default: $HOME/.config/letsencrypt/live, certbot's config dir
#                                 as set in ~/.config/letsencrypt/cli.ini; not XDG_CONFIG_HOME)
#   PROTON_PASS_PERSONAL_ACCESS_TOKEN  Proton Pass token (pst_...::...); enables Proton Pass
#   PROTON_PASS_AGENT_REASON      audit-log reason for a Proton Pass agent (default: names the certificate)
#   ARKKVM_PASS_TOKEN_FILE           file holding the token instead; enables Proton Pass
#   ARKKVM_PASS_CLI                  pass-cli program (default: on PATH, ~/.local/bin, /usr/local/bin)
set -eu

USER_CONFIG="${XDG_CONFIG_HOME:-${HOME:-}/.config}"
case $USER_CONFIG in /*) ;; *) USER_CONFIG="${HOME:-}/.config" ;; esac

die() {
    echo "arkkvm-deploy-hook: $*" >&2
    exit 1
}

if [ -n "${ARKKVM_CERT_UPDATER_ENV:-}" ]; then
    ENV_FILE=$ARKKVM_CERT_UPDATER_ENV
elif [ -f "$USER_CONFIG/arkkvm-cert-updater/config.env" ]; then
    ENV_FILE="$USER_CONFIG/arkkvm-cert-updater/config.env"
else
    die "no config.env found; set ARKKVM_CERT_UPDATER_ENV or create $USER_CONFIG/arkkvm-cert-updater/config.env"
fi

# conf_get KEY: the value of KEY from the environment if it is set there (even to an
# empty value, which overrides the file, as it does for the updater), else from the
# env file. Understands the same format as the updater: KEY=VALUE, optional "export ",
# optional single or double quotes, # comments. The last assignment wins.
conf_get() {
    if eval "[ \"\${$1+set}\" = set ]"; then
        eval "_v=\${$1}"
        printf '%s' "$_v"
        return
    fi
    _v=
    if [ -r "$ENV_FILE" ]; then
        _v=$(sed -n "s/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}$1[[:space:]]*=[[:space:]]*\(.*[^[:space:]]\)\{0,1\}[[:space:]]*\$/\2/p" "$ENV_FILE" | tail -n 1)
        case $_v in
            \"*\") _v=${_v#\"}; _v=${_v%\"} ;;
            \'*\') _v=${_v#\'}; _v=${_v%\'} ;;
        esac
    fi
    printf '%s' "$_v"
}

# find_program NAME CONFIGURED: CONFIGURED if set, else NAME on PATH or in a usual location.
find_program() {
    if [ -n "$2" ]; then
        printf '%s' "$2"
        return
    fi
    if command -v "$1" >/dev/null 2>&1; then
        command -v "$1"
        return
    fi
    for _dir in "${HOME:-/nonexistent}/.local/bin" /usr/local/bin; do
        if [ -x "$_dir/$1" ]; then
            printf '%s' "$_dir/$1"
            return
        fi
    done
}

BIN=$(find_program arkkvm-cert-updater "$(conf_get ARKKVM_UPDATER_BIN)")
[ -n "$BIN" ] || die "arkkvm-cert-updater not found; set ARKKVM_UPDATER_BIN"

CERT_NAME=$(conf_get ARKKVM_CERT_NAME)
[ -n "$CERT_NAME" ] || die "ARKKVM_CERT_NAME is not set in $ENV_FILE or the environment"

if [ "${1:-}" = "--reapply" ]; then
    shift
    LIVE_DIR=$(conf_get ARKKVM_LETSENCRYPT_LIVE)
    [ -n "$LIVE_DIR" ] || LIVE_DIR="${HOME:-}/.config/letsencrypt/live"
    RENEWED_LINEAGE="$LIVE_DIR/$CERT_NAME"
    [ -d "$RENEWED_LINEAGE" ] || die "--reapply: certificate directory $RENEWED_LINEAGE does not exist; set ARKKVM_LETSENCRYPT_LIVE"
    export RENEWED_LINEAGE
fi

if [ -z "${RENEWED_LINEAGE:-}" ]; then
    die "RENEWED_LINEAGE is not set; run this from certbot --deploy-hook, or with --reapply"
fi

# Guard: only the ArkKVM's certificate is installed on the ArkKVM.
if [ "${RENEWED_LINEAGE##*/}" != "$CERT_NAME" ]; then
    echo "arkkvm-deploy-hook: ${RENEWED_LINEAGE##*/} is not $CERT_NAME; skipping" >&2
    exit 0
fi

PAT=$(conf_get PROTON_PASS_PERSONAL_ACCESS_TOKEN)
TOKEN_FILE=$(conf_get ARKKVM_PASS_TOKEN_FILE)
if [ -z "$PAT" ] && [ -z "$TOKEN_FILE" ]; then
    exec "$BIN" --certbot --env-file "$ENV_FILE" "$@"
fi

# --- Proton Pass -------------------------------------------------------------

PASS_CLI=$(find_program pass-cli "$(conf_get ARKKVM_PASS_CLI)")
[ -n "$PASS_CLI" ] || die "pass-cli not found; set ARKKVM_PASS_CLI"

if [ -z "$PAT" ]; then
    [ -r "$TOKEN_FILE" ] || die "cannot read Proton Pass token file $TOKEN_FILE"
    PAT=$(tr -d '[:space:]' <"$TOKEN_FILE")
    # Accept the line exactly as `pass-cli agent create` prints it.
    PAT=${PAT#PROTON_PASS_PERSONAL_ACCESS_TOKEN=}
    [ -n "$PAT" ] || die "Proton Pass token file $TOKEN_FILE is empty"
fi
# Keep the token out of every process except `pass-cli login`.
unset PROTON_PASS_PERSONAL_ACCESS_TOKEN

# Proton Pass agents must give a reason, which goes into the agent's audit log
# (`pass-cli agent monitor`). Plain personal access tokens ignore it.
PROTON_PASS_AGENT_REASON=$(conf_get PROTON_PASS_AGENT_REASON)
if [ -z "$PROTON_PASS_AGENT_REASON" ]; then
    PROTON_PASS_AGENT_REASON="arkkvm-cert-updater: install certificate ${RENEWED_LINEAGE##*/} on the ArkKVM"
fi
[ "${#PROTON_PASS_AGENT_REASON}" -le 300 ] || die "PROTON_PASS_AGENT_REASON is longer than 300 characters"
export PROTON_PASS_AGENT_REASON

# Use a private, throwaway pass-cli session so the token login never touches the
# user's own pass-cli session or keyring. With the fs key provider, pass-cli keeps
# both its session database and its encryption key inside PROTON_PASS_SESSION_DIR.
umask 077
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/arkkvm-pass.XXXXXXXX") || die "cannot create a temporary directory"
PROTON_PASS_SESSION_DIR="$WORK_DIR/session"
PROTON_PASS_KEY_PROVIDER=fs
export PROTON_PASS_SESSION_DIR PROTON_PASS_KEY_PROVIDER
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    "$PASS_CLI" logout --force >/dev/null 2>&1 || true
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$PROTON_PASS_SESSION_DIR"

# A copy of the env file without the token, for `pass-cli run` (which exports every
# entry to the updater) and the updater itself.
RUN_ENV_FILE="$WORK_DIR/config.env"
if [ -r "$ENV_FILE" ]; then
    grep -v "^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}PROTON_PASS_PERSONAL_ACCESS_TOKEN[[:space:]]*=" "$ENV_FILE" >"$RUN_ENV_FILE" || true
else
    : >"$RUN_ENV_FILE"
fi

# Personal access token sessions last two hours, so log in on every run. The token
# goes through the environment, never the command line.
PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" "$PASS_CLI" login >/dev/null || die "pass-cli login failed"
unset PAT

status=0
"$PASS_CLI" run --env-file "$RUN_ENV_FILE" -- "$BIN" --certbot --env-file "$RUN_ENV_FILE" "$@" || status=$?
exit "$status"
