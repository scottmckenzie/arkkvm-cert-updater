"""Command-line interface and certbot deploy hook entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path

from .certs import CertificateError, load_lineage
from .config import APP_NAME, ENV_FILE_VAR, ConfigError, find_env_file, load_env, resolve_config
from .device import DeviceError, LoginError, ProtocolError, RefusedError
from .tls import IdentityError
from .updater import Deps, Outcome, VerifyError, run

log = logging.getLogger("arkkvm_cert_updater")

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_CERT = 3
EXIT_IDENTITY = 4
EXIT_LOGIN = 5
EXIT_REFUSED = 6
EXIT_VERIFY = 7
EXIT_DEVICE = 8

# Subclasses first: LoginError, RefusedError and ProtocolError are all DeviceError.
_EXIT_CODES: tuple[tuple[type[BaseException], int], ...] = (
    (ConfigError, EXIT_CONFIG),
    (CertificateError, EXIT_CERT),
    (IdentityError, EXIT_IDENTITY),
    (LoginError, EXIT_LOGIN),
    (RefusedError, EXIT_REFUSED),
    (VerifyError, EXIT_VERIFY),
    (ProtocolError, EXIT_DEVICE),
    (DeviceError, EXIT_DEVICE),
    (OSError, EXIT_DEVICE),
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "Install a Let's Encrypt certificate on an ArkKVM device. Settings come from the environment "
            "or an env file (ARKKVM_URL, ARKKVM_PASSWORD, ARKKVM_CERT_NAME, ...); the password is "
            "never accepted on the command line."
        ),
    )
    p.add_argument(
        "--env-file",
        type=Path,
        help=f"read settings from this KEY=VALUE file (default: ${ENV_FILE_VAR} if set, else ~/.config/{APP_NAME}/config.env)",
    )
    p.add_argument(
        "--certbot",
        action="store_true",
        help="run as a certbot deploy hook: use the lineage in $RENEWED_LINEAGE, and skip other certificates",
    )
    p.add_argument(
        "--lineage", type=Path, help="certbot lineage folder (default: ARKKVM_LETSENCRYPT_LIVE/ARKKVM_CERT_NAME)"
    )
    p.add_argument("--check", action="store_true", help="log in and compare the certificates, but change nothing")
    p.add_argument("--force", action="store_true", help="install even if the device already serves this certificate")
    p.add_argument("-v", "--verbose", action="store_true", help="enable debug logging and show tracebacks")
    return p


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s: %(message)s", stream=sys.stderr)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Debug output from the HTTP stack is noisy and must never be switched on by -v or the root level.
    for name in ("urllib3", "requests"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _exit_code(exc: BaseException) -> int | None:
    for kind, code in _EXIT_CODES:
        if isinstance(exc, kind):
            return code
    return None


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    deps: Deps | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    base_env = os.environ if environ is None else environ

    try:
        env_file: Path | None = args.env_file or find_env_file(base_env)
        env = load_env(env_file, base_env)
        config = resolve_config(env)

        if args.certbot:
            renewed = base_env.get("RENEWED_LINEAGE", "")
            if not renewed:
                raise ConfigError("--certbot: RENEWED_LINEAGE is not set; is this running as a certbot deploy hook?")
            lineage_path = Path(renewed)
            if lineage_path.name != config.cert_name:
                log.info("%s is not the KVM certificate; skipping", lineage_path.name)
                return EXIT_OK
        elif args.lineage is not None:
            lineage_path = args.lineage
        else:
            lineage_path = config.live_dir / config.cert_name

        lineage = load_lineage(lineage_path)
        outcome = run(config, lineage, force=args.force, check_only=args.check, deps=deps)
    except Exception as exc:
        code = _exit_code(exc)
        if code is None:
            raise
        print(f"error: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return code

    if outcome is Outcome.ALREADY_INSTALLED:
        log.info("done: the certificate is already installed")
    elif outcome is Outcome.INSTALLED:
        log.info("done: the certificate was installed")
    else:
        log.info("done: check complete")
    return EXIT_OK


def main_exit() -> None:
    sys.exit(main())
