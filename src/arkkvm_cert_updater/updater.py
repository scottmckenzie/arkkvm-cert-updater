"""The install flow: decide whether to install, install (the device reboots), then wait for the new certificate.

Two TLS contexts are built from the same settings and never shared:

* the **trust** context goes to :func:`choose_trust` and from there into the device session, which may
  adjust a context it is given;
* the **check** context is only used for this module's own checks: "is it already installed?" and the
  wait after the reboot. Success after a reboot is judged with a context nothing else has touched.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import device, tls
from .certs import Lineage, check_usable_for, format_fingerprint, sha256_fingerprint
from .config import Config

log = logging.getLogger(__name__)

POLL_INTERVAL = 10.0
PROBE_TIMEOUT = 10.0  # one TLS handshake attempt; also the connect timeout for the identity checks


class Outcome(enum.Enum):
    ALREADY_INSTALLED = "already installed"
    INSTALLED = "installed"
    CHECKED = "checked"


class VerifyError(Exception):
    """After the reset, the KVM did not serve the new certificate (verified) before the deadline."""


def wait_for_certificate(
    host: str,
    port: int,
    *,
    expected: bytes,
    context: ssl.SSLContext,
    timeout: float,
    interval: float = POLL_INTERVAL,
    served: Callable[..., tuple[bytes, bool]] = tls.served_certificate,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Poll until the KVM serves a certificate with SHA-256 ``expected`` that also passes ``context``.

    The KVM usually keeps serving the old certificate for a while, then drops off the network while it
    restarts. Old certificates and network errors (``OSError``, which includes TLS errors) both mean
    "keep waiting". Raises :class:`VerifyError` at the deadline, saying what was served last.
    """
    deadline = monotonic() + timeout
    last_seen: str | None = None  # the last fingerprint served, with a note if it failed verification
    unreachable = False  # whether the most recent probe failed at the network level
    announced = False
    while True:
        probe_timeout = max(0.1, min(PROBE_TIMEOUT, deadline - monotonic()))
        try:
            der, verified = served(host, port, context, timeout=probe_timeout)
            fp = sha256_fingerprint(der)
            unreachable = False
            last_seen = format_fingerprint(fp)
            if fp == expected:
                if verified:
                    log.info("the KVM is serving the new certificate %s", last_seen)
                    return
                last_seen += f" (the new certificate, but it fails verification for {host})"
                log.debug("the new certificate is served but fails verification; still waiting")
            else:
                log.debug("the KVM still serves %s; waiting", last_seen)
        except OSError as exc:
            unreachable = True
            if not announced:
                log.info("the KVM is unreachable, presumably rebooting; waiting up to %g seconds", timeout)
                announced = True
            log.debug("probe failed: %s", type(exc).__name__)

        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(interval, remaining))

    if last_seen is None:
        seen = "it stayed unreachable"
    elif unreachable:
        seen = f"it is unreachable; the last certificate it served was {last_seen}"
    else:
        seen = f"it is serving {last_seen}"
    raise VerifyError(
        f"the KVM did not serve the new certificate {format_fingerprint(expected)} "
        f"within {timeout:g} seconds after the reboot: {seen}"
    )


@dataclass
class Deps:
    """What :func:`run` talks to the outside world with; tests replace these.

    ``check_login`` and ``install`` are synchronous; the defaults run the device coroutines to completion.
    """

    served: Callable[..., tuple[bytes, bool]] = field(default=tls.served_certificate)
    choose_trust: Callable[..., tls.Trust] = field(default=tls.choose_trust)
    check_login: Callable[..., None] = field(default=lambda *a, **k: asyncio.run(device.check_login(*a, **k)))
    install: Callable[..., None] = field(default=lambda *a, **k: asyncio.run(device.install_certificate(*a, **k)))
    wait: Callable[..., None] = field(default=wait_for_certificate)
    check_usable: Callable[[Lineage, str], None] = field(default=check_usable_for)


def _served_matches(config: Config, lineage: Lineage, check_context: ssl.SSLContext, deps: Deps) -> tuple[bool, str]:
    """Whether the KVM already serves the lineage's certificate, verified; and its fingerprint for logs."""
    der, verified = deps.served(config.host, config.port, check_context, timeout=PROBE_TIMEOUT)
    fp = sha256_fingerprint(der)
    return fp == lineage.fingerprint and verified, format_fingerprint(fp)


def run(
    config: Config,
    lineage: Lineage,
    *,
    force: bool = False,
    check_only: bool = False,
    deps: Deps | None = None,
) -> Outcome:
    """Install ``lineage`` on the KVM unless it's already there; or, with ``check_only``, just check."""
    deps = deps or Deps()
    # Before touching the KVM, even for --check: a certificate that can't verify for this host would reboot
    # the KVM into a certificate nothing trusts.
    deps.check_usable(lineage, config.host)
    check_context = tls.verification_context(lineage.chain_pem, config.ca_bundle)

    served_matches: tuple[bool, str] | None = None
    if not force or check_only:
        served_matches = _served_matches(config, lineage, check_context, deps)
        if served_matches[0] and not check_only:
            log.info("already installed: the KVM serves %s", served_matches[1])
            return Outcome.ALREADY_INSTALLED

    # A separate context for the device session: it may change a context it is given. The KVM still serves
    # the old certificate here, which may have been issued under an earlier intermediate than the new
    # lineage's, so offer every intermediate certbot has kept (as intermediates only: roots stay the CAs).
    trust = deps.choose_trust(
        config.host,
        config.port,
        context=tls.verification_context(lineage.issuer_chains_pem or lineage.chain_pem, config.ca_bundle),
        pin=config.tls_fingerprint,
        timeout=PROBE_TIMEOUT,
    )
    if trust.pin is not None:
        log.info("the KVM's certificate fails verification but matches ARKKVM_TLS_FINGERPRINT; using the pin")

    if check_only:
        deps.check_login(config.url, config.password, trust=trust, timeout=config.timeout)
        matches, fingerprint = served_matches or (False, "")
        if matches:
            log.info("the served certificate %s matches the lineage %s", fingerprint, lineage.name)
        else:
            log.info("the served certificate %s does not match the lineage %s", fingerprint, lineage.name)
        log.info("login OK")
        return Outcome.CHECKED

    deps.install(config.url, config.password, lineage.certs_pem, lineage.key_pem, trust=trust, timeout=config.timeout)
    log.info("certificate installed and the KVM rebooted; waiting for it to serve the new certificate")
    deps.wait(
        config.host,
        config.port,
        expected=lineage.fingerprint,
        context=check_context,
        timeout=config.reset_timeout,
    )
    log.info("installed the certificate for %s", lineage.name)
    return Outcome.INSTALLED
