"""Install flow tests: fakes for the decisions and the device calls, plus wait_for_certificate."""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

import pytest

from arkkvm_cert_updater.certs import Lineage, format_fingerprint, sha256_fingerprint
from arkkvm_cert_updater.config import Config
from arkkvm_cert_updater.device import LoginError, RefusedError
from arkkvm_cert_updater.tls import IdentityError, Trust
from arkkvm_cert_updater.updater import Deps, Outcome, VerifyError, run, wait_for_certificate

PASSWORD = 'pä"&=ss-secret'
NEW_DER = b"new certificate der"
OLD_DER = b"old certificate der"
NEW_FP = sha256_fingerprint(NEW_DER)
OLD_FP = sha256_fingerprint(OLD_DER)


def make_config(**overrides) -> Config:
    values = {
        "url": "https://kvm.test",
        "host": "kvm.test",
        "port": 443,
        "password": PASSWORD,
        "cert_name": "kvm.test",
        "tls_fingerprint": None,
        "ca_bundle": None,
        "reset_timeout": 300.0,
        "timeout": 17.0,
        "live_dir": Path("/nonexistent/live"),
    }
    values.update(overrides)
    return Config(**values)


LINEAGE = Lineage(
    name="kvm.test",
    leaf_der=NEW_DER,
    certs_pem="CERTS",
    key_pem="KEY",
    chain_pem=b"",
    fingerprint=NEW_FP,
)


class Harness:
    """Fake dependencies for ``run``, recording what they were given."""

    def __init__(self, *, served: bytes = OLD_DER, verified: bool = True, pin: bytes | None = None) -> None:
        self.served = served
        self.is_verified = verified
        self.pin = pin
        self.calls: list[str] = []
        self.args: dict[str, tuple] = {}
        self.kwargs: dict[str, dict] = {}
        self.fail: dict[str, Exception] = {}
        self.trust_contexts: list[ssl.SSLContext] = []
        self.verified_contexts: list[ssl.SSLContext] = []
        self.wait_calls: list[dict] = []

    def _record(self, name: str, args: tuple, kwargs: dict) -> None:
        self.calls.append(name)
        self.args[name] = args
        self.kwargs[name] = kwargs
        if name in self.fail:
            raise self.fail[name]

    def served_certificate(self, host, port, context, *, timeout):
        self.verified_contexts.append(context)
        return self.fetch(host, port, timeout=timeout), self.is_verified

    def fetch(self, host, port, *, timeout):
        return self.served

    def verified(self, host, port, context, *, timeout):
        self.verified_contexts.append(context)
        return self.is_verified

    def choose_trust(self, host, port, *, context, pin, timeout):
        self.trust_contexts.append(context)
        self._record("choose_trust", (host, port), {"pin": pin})
        return Trust(context, self.pin)

    def check_login(self, *args, **kwargs):
        self._record("check_login", args, kwargs)

    def install(self, *args, **kwargs):
        self._record("install", args, kwargs)

    def wait(self, host, port, **kwargs):
        self.calls.append("wait")
        self.wait_calls.append({"host": host, "port": port, **kwargs})

    def deps(self) -> Deps:
        return Deps(
            served=self.served_certificate,
            choose_trust=self.choose_trust,
            check_login=self.check_login,
            install=self.install,
            wait=self.wait,
            check_usable=self.check_usable,
        )

    def check_usable(self, lineage: Lineage, host: str) -> None:
        self.usable_checked = (lineage.name, host)


# --- run ----------------------------------------------------------------------------------------


def test_already_installed_skips_login_and_install(caplog):
    h = Harness(served=NEW_DER)
    with caplog.at_level(logging.INFO):
        assert run(make_config(), LINEAGE, deps=h.deps()) is Outcome.ALREADY_INSTALLED
    assert h.calls == []
    assert h.trust_contexts == []
    assert "already installed" in caplog.text


def test_matching_but_unverified_is_installed():
    h = Harness(served=NEW_DER, verified=False)
    assert run(make_config(), LINEAGE, deps=h.deps()) is Outcome.INSTALLED
    assert h.calls == ["choose_trust", "install", "wait"]


def test_force_installs_even_if_matching():
    h = Harness(served=NEW_DER)
    assert run(make_config(), LINEAGE, force=True, deps=h.deps()) is Outcome.INSTALLED
    assert h.calls == ["choose_trust", "install", "wait"]


def test_install_then_wait():
    h = Harness(served=OLD_DER)
    config = make_config(reset_timeout=123.0)
    assert run(config, LINEAGE, deps=h.deps()) is Outcome.INSTALLED
    assert h.calls == ["choose_trust", "install", "wait"]
    assert h.args["install"] == ("https://kvm.test", PASSWORD, "CERTS", "KEY")
    assert h.kwargs["install"]["timeout"] == 17.0
    assert isinstance(h.kwargs["install"]["trust"], Trust)
    [call] = h.wait_calls
    assert call["expected"] == LINEAGE.fingerprint
    assert call["timeout"] == 123.0
    assert (call["host"], call["port"]) == ("kvm.test", 443)


def test_pin_passed_and_logged_when_verification_fails(caplog):
    pin = b"\x01" * 32
    h = Harness(pin=pin)
    with caplog.at_level(logging.INFO):
        run(make_config(tls_fingerprint=pin), LINEAGE, deps=h.deps())
    assert h.kwargs["choose_trust"]["pin"] == pin
    assert h.kwargs["install"]["trust"].pin == pin
    assert "ARKKVM_TLS_FINGERPRINT" in caplog.text
    assert "BMC" not in caplog.text


def test_session_and_check_contexts_are_separate():
    """The context handed to the device session is never the one used for our own checks."""
    h = Harness(served=NEW_DER, verified=False)
    run(make_config(), LINEAGE, deps=h.deps())
    [trust_context] = h.trust_contexts
    [check_context] = h.verified_contexts
    assert trust_context is not check_context
    assert h.wait_calls[0]["context"] is check_context
    assert check_context.check_hostname is True
    assert check_context.verify_mode == ssl.CERT_REQUIRED


def test_check_only(caplog):
    h = Harness(served=NEW_DER)
    with caplog.at_level(logging.INFO):
        assert run(make_config(), LINEAGE, check_only=True, deps=h.deps()) is Outcome.CHECKED
    assert h.calls == ["choose_trust", "check_login"]
    assert h.args["check_login"] == ("https://kvm.test", PASSWORD)
    assert h.kwargs["check_login"]["timeout"] == 17.0
    assert "login OK" in caplog.text
    assert "matches" in caplog.text
    assert PASSWORD not in caplog.text


def test_check_only_reports_mismatch(caplog):
    h = Harness(served=OLD_DER)
    with caplog.at_level(logging.INFO):
        assert run(make_config(), LINEAGE, check_only=True, deps=h.deps()) is Outcome.CHECKED
    assert "does not match" in caplog.text
    assert format_fingerprint(OLD_FP) in caplog.text


def test_check_only_login_failure_propagates():
    h = Harness()
    h.fail["check_login"] = LoginError("login rejected")
    with pytest.raises(LoginError):
        run(make_config(), LINEAGE, check_only=True, deps=h.deps())


def test_login_error_propagates_from_install():
    h = Harness()
    h.fail["install"] = LoginError("login rejected")
    with pytest.raises(LoginError):
        run(make_config(), LINEAGE, deps=h.deps())
    assert "wait" not in h.calls


def test_refused_propagates_without_wait():
    h = Harness()
    h.fail["install"] = RefusedError("refused")
    with pytest.raises(RefusedError):
        run(make_config(), LINEAGE, deps=h.deps())
    assert h.wait_calls == []


def test_identity_error_propagates_before_login():
    h = Harness()
    h.fail["choose_trust"] = IdentityError("fails verification")
    with pytest.raises(IdentityError):
        run(make_config(), LINEAGE, deps=h.deps())
    assert h.calls == ["choose_trust"]


def test_fetch_network_failure_propagates_without_login():
    h = Harness()

    def refuse(host, port, *, timeout):
        raise ConnectionRefusedError("refused")

    deps = h.deps()
    deps.served = lambda host, port, context, *, timeout: refuse(host, port, timeout=timeout)
    with pytest.raises(OSError):
        run(make_config(), LINEAGE, deps=deps)
    assert h.calls == []


def test_wait_failure_propagates():
    h = Harness()
    deps = h.deps()

    def wait(host, port, **kwargs):
        raise VerifyError("timed out")

    deps.wait = wait
    with pytest.raises(VerifyError):
        run(make_config(), LINEAGE, deps=deps)
    assert h.calls == ["choose_trust", "install"]


# --- wait_for_certificate -----------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _sequence(items):
    it = iter(items)

    def fetch(host, port, *, timeout):
        item = next(it)
        if isinstance(item, BaseException):
            raise item
        return item

    return fetch


def _served(fetch, verified):
    """Adapt the fetch/verify fakes to ``served``: one probe, verification asked only for the new certificate."""

    def served(host, port, context, *, timeout):
        der = fetch(host, port, timeout=timeout)
        return der, der == NEW_DER and verified(host, port, context, timeout=timeout)

    return served


def _wait(clock: FakeClock, fetch, verified=lambda *a, **k: True, timeout: float = 300.0):
    wait_for_certificate(
        "kvm.test",
        443,
        expected=NEW_FP,
        context=ssl.create_default_context(),
        timeout=timeout,
        served=_served(fetch, verified),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )


def test_wait_success_after_old_cert_then_unreachable_then_new(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.INFO):
        _wait(clock, _sequence([OLD_DER, OLD_DER, ConnectionRefusedError(), OSError("reset"), NEW_DER]))
    assert clock.sleeps == [10.0, 10.0, 10.0, 10.0]
    unreachable = [r for r in caplog.records if "unreachable" in r.getMessage()]
    assert len(unreachable) == 1
    assert unreachable[0].levelno == logging.INFO


def test_wait_timeout_names_last_fingerprint():
    clock = FakeClock()

    def always_old(host, port, *, timeout):
        return OLD_DER

    with pytest.raises(VerifyError) as exc:
        _wait(clock, always_old, timeout=95.0)
    assert format_fingerprint(OLD_FP) in str(exc.value)
    assert sum(clock.sleeps) <= 95.0 + 10.0
    assert len(clock.sleeps) >= 9  # it kept polling instead of failing on the first old answer


def test_wait_timeout_unreachable():
    clock = FakeClock()

    def down(host, port, *, timeout):
        raise ConnectionRefusedError()

    with pytest.raises(VerifyError, match="unreachable"):
        _wait(clock, down, timeout=30.0)
    assert sum(clock.sleeps) <= 40.0


def test_wait_timeout_unreachable_after_old_names_both():
    clock = FakeClock()
    with pytest.raises(VerifyError) as exc:
        _wait(clock, _sequence([OLD_DER] + [ConnectionRefusedError()] * 10), timeout=30.0)
    assert "unreachable" in str(exc.value)
    assert format_fingerprint(OLD_FP) in str(exc.value)


def test_wait_requires_verification():
    clock = FakeClock()
    calls = []

    def new(host, port, *, timeout):
        return NEW_DER

    def not_verified(host, port, context, *, timeout):
        calls.append(context)
        return False

    with pytest.raises(VerifyError) as exc:
        _wait(clock, new, verified=not_verified, timeout=50.0)
    assert len(calls) >= 5
    assert "verification" in str(exc.value)
    assert format_fingerprint(NEW_FP) in str(exc.value)


def test_wait_verify_network_failure_is_still_resetting():
    clock = FakeClock()
    results = iter([ConnectionResetError(), True])

    def verified(host, port, context, *, timeout):
        item = next(results)
        if isinstance(item, BaseException):
            raise item
        return item

    _wait(clock, _sequence([NEW_DER, NEW_DER]), verified=verified)
    assert clock.sleeps == [10.0]


def test_wait_probe_timeout_is_bounded():
    clock = FakeClock()
    timeouts = []

    def fetch(host, port, *, timeout):
        timeouts.append(timeout)
        raise ConnectionRefusedError()

    with pytest.raises(VerifyError):
        _wait(clock, fetch, timeout=25.0)
    assert all(0 < t <= 10.0 for t in timeouts)


def test_choose_trust_gets_archived_issuer_chains_but_wait_uses_the_new_chain(pki):
    """The served (old) certificate may need an earlier intermediate; the new one must verify with its own chain."""
    import dataclasses

    from conftest import second_intermediate

    pki_b = second_intermediate(pki)
    lineage = dataclasses.replace(
        LINEAGE, chain_pem=pki_b.intermediate_pem, issuer_chains_pem=pki.intermediate_pem + pki_b.intermediate_pem
    )
    h = Harness()
    seen: dict[str, ssl.SSLContext] = {}

    def choose_trust(host, port, *, context, pin, timeout):
        seen["trust"] = context
        return Trust(context, None)

    deps = h.deps()
    deps.choose_trust = choose_trust
    run(make_config(), lineage, deps=deps)

    def intermediates(context: ssl.SSLContext) -> set[str]:
        # ssl's own view of the store: no re-parsing, since it can include system CAs too, some of them with no
        # common name or with serial numbers newer versions of cryptography warn about.
        names = {
            value
            for cert in context.get_ca_certs()
            for rdn in cert.get("subject", ())
            for key, value in rdn
            if key == "commonName"
        }
        return {n for n in names if n.startswith("Test Intermediate CA")}

    assert intermediates(seen["trust"]) == {"Test Intermediate CA", "Test Intermediate CA B"}
    assert intermediates(h.wait_calls[0]["context"]) == {"Test Intermediate CA B"}
    assert h.usable_checked == ("kvm.test", "kvm.test")
