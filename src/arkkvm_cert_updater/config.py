"""Configuration: env file lookup, parsing and validation of the KVM settings."""

from __future__ import annotations

import logging
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("arkkvm_cert_updater")

APP_NAME = "arkkvm-cert-updater"
ENV_FILE_VAR = "ARKKVM_CERT_UPDATER_ENV"

DEFAULT_RESET_TIMEOUT = 300.0
DEFAULT_TIMEOUT = 20.0


class ConfigError(Exception):
    """Raised for missing or invalid configuration."""


@dataclass(frozen=True)
class Config:
    url: str
    host: str
    port: int
    password: str
    cert_name: str
    tls_fingerprint: bytes | None
    ca_bundle: Path | None
    reset_timeout: float
    timeout: float
    live_dir: Path


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple ``KEY=VALUE`` file (blank lines and ``#`` comments ignored).

    Values may be wrapped in single or double quotes. An optional leading
    ``export`` is accepted so the same file can be sourced by a shell.
    """
    result: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key] = value
    return result


def user_config_dir(environ: Mapping[str, str]) -> Path:
    """``$XDG_CONFIG_HOME/arkkvm-cert-updater``, defaulting to ``~/.config/arkkvm-cert-updater``."""
    xdg = environ.get("XDG_CONFIG_HOME")
    if xdg and Path(xdg).is_absolute():  # the XDG spec says to ignore relative paths
        return Path(xdg) / APP_NAME
    home = environ.get("HOME")
    return (Path(home) if home else Path.home()) / ".config" / APP_NAME


def find_env_file(environ: Mapping[str, str]) -> Path | None:
    """Pick the env file when none is given explicitly.

    ``$ARKKVM_CERT_UPDATER_ENV`` wins (and must exist), then the user's own config file.
    There is deliberately no system-wide fallback.
    """
    explicit = environ.get(ENV_FILE_VAR)
    if explicit:
        return Path(explicit)
    candidate = user_config_dir(environ) / "config.env"
    return candidate if candidate.is_file() else None


def check_env_file_permissions(path: Path) -> None:
    """Warn when a file that may hold secrets is readable by others or owned by someone else."""
    try:
        st = path.stat()
    except OSError:
        return
    if st.st_mode & 0o077:
        log.warning(
            "%s is accessible by other users (mode %03o) but may contain secrets; run: chmod 600 %s",
            path,
            st.st_mode & 0o777,
            path,
        )
    getuid = getattr(os, "getuid", None)
    if getuid is not None and st.st_uid not in (getuid(), 0):
        log.warning("%s is owned by another user (uid %d); they can change its settings", path, st.st_uid)


def load_env(env_file: Path | None, environ: Mapping[str, str]) -> dict[str, str]:
    """Combine the env file (if any) with the process environment, which takes priority."""
    env: dict[str, str] = {}
    if env_file is not None:
        log.debug("reading settings from %s", env_file)
        try:
            env.update(parse_env_file(env_file))
        except OSError as exc:
            raise ConfigError(f"cannot read env file {env_file}: {exc}") from exc
        check_env_file_permissions(env_file)
    env.update(environ)
    return env


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _ascii_host(host: str) -> str:
    """The host as certificates and TLS name it: internationalized names in their IDNA (``xn--``) form.

    ``urlsplit`` leaves ``https://bücher.example`` as ``bücher.example``, but a certificate's
    subjectAltName holds ``xn--bcher-kva.example``, and the TLS probes and HTTP client must all use the
    same name. IP addresses and plain ASCII names are returned unchanged.
    """
    if host.isascii() or ":" in host:
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigError(f"ARKKVM_URL host {host!r} is not a valid internationalized domain name: {exc}") from None


def _parse_url(value: str) -> tuple[str, str, int]:
    try:
        parts = urlsplit(value)
        port = parts.port
        host = parts.hostname
    except ValueError as exc:
        raise ConfigError(f"ARKKVM_URL is not a valid URL: {exc}") from exc
    if parts.scheme != "https":
        raise ConfigError("ARKKVM_URL must start with https://")
    if not host:
        raise ConfigError("ARKKVM_URL has no host name")
    host = _ascii_host(host)
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ConfigError("ARKKVM_URL must be just https://host[:port], without a path or credentials")
    if port == 0:
        raise ConfigError("ARKKVM_URL has an invalid port 0")
    shown_host = f"[{host}]" if ":" in host else host
    netloc = shown_host if port in (None, 443) else f"{shown_host}:{port}"
    return f"https://{netloc}", host, port or 443


def _parse_fingerprint(value: str) -> bytes:
    digits = value.replace(":", "").strip()
    try:
        raw = bytes.fromhex(digits)
    except ValueError:
        raise ConfigError("ARKKVM_TLS_FINGERPRINT must be hexadecimal digits, optionally separated by colons") from None
    if len(raw) != 32:
        raise ConfigError(f"ARKKVM_TLS_FINGERPRINT must be a SHA-256 fingerprint (32 bytes), got {len(raw)}")
    return raw


def _parse_timeout(name: str, value: str) -> float:
    try:
        timeout = float(value)
    except ValueError:
        raise ConfigError(f"{name} must be a number of seconds, got {value!r}") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {value!r}")
    return timeout


def resolve_config(env: Mapping[str, str]) -> Config:
    """Validate the settings in ``env`` and build a :class:`Config`; errors name the setting."""
    url = _required(env, "ARKKVM_URL")
    url, host, port = _parse_url(url)
    # Verbatim: leading or trailing spaces can be part of a password. Only reject a blank one.
    password = env.get("ARKKVM_PASSWORD", "")
    if not password.strip():
        raise ConfigError("ARKKVM_PASSWORD is required")
    if password.strip().startswith("pass://"):
        # Never echo the value: it names where the secret lives.
        raise ConfigError(
            "ARKKVM_PASSWORD is an unresolved Proton Pass reference (pass://...); run through the certbot deploy "
            "hook with a Proton Pass agent token configured, so the hook resolves it"
        )
    cert_name = _required(env, "ARKKVM_CERT_NAME")

    fingerprint_text = env.get("ARKKVM_TLS_FINGERPRINT", "").strip()
    fingerprint = _parse_fingerprint(fingerprint_text) if fingerprint_text else None

    ca_text = env.get("ARKKVM_CA_BUNDLE", "").strip()
    ca_bundle = Path(ca_text) if ca_text else None
    if ca_bundle is not None and not ca_bundle.is_file():
        raise ConfigError(f"ARKKVM_CA_BUNDLE: {ca_bundle} is not an existing file")

    reset_text = env.get("ARKKVM_RESET_TIMEOUT", "").strip()
    reset_timeout = _parse_timeout("ARKKVM_RESET_TIMEOUT", reset_text) if reset_text else DEFAULT_RESET_TIMEOUT

    timeout_text = env.get("ARKKVM_TIMEOUT", "").strip()
    timeout = _parse_timeout("ARKKVM_TIMEOUT", timeout_text) if timeout_text else DEFAULT_TIMEOUT

    live_text = env.get("ARKKVM_LETSENCRYPT_LIVE", "").strip()
    if live_text:
        live_dir = Path(live_text)
        if not live_dir.is_absolute():
            raise ConfigError(f"ARKKVM_LETSENCRYPT_LIVE must be an absolute path, got {live_text!r}")
    else:
        home = env.get("HOME")
        live_dir = (Path(home) if home else Path.home()) / ".config" / "letsencrypt" / "live"

    return Config(
        url=url,
        host=host,
        port=port,
        password=password,
        cert_name=cert_name,
        tls_fingerprint=fingerprint,
        ca_bundle=ca_bundle,
        reset_timeout=reset_timeout,
        timeout=timeout,
        live_dir=live_dir,
    )
