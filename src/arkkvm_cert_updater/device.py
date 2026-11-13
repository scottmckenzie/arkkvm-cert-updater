"""Talk to the KVM's own web API: local login, then ``setTLSState`` over a WebRTC ``rpc`` data channel."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
from collections.abc import AsyncIterator, Iterator
from importlib.metadata import version
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import aiohttp
from aiortc import RTCPeerConnection, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp

from .tls import IdentityError, Trust, aiohttp_ssl

LOG = logging.getLogger(__name__)


class DeviceError(Exception):
    """The KVM could not be talked to or did something unexpected (exit 8)."""


class LoginError(DeviceError):
    """The KVM rejected the login: HTTP 401/403 from ``/auth/login-local`` (exit 5)."""


class RefusedError(DeviceError):
    """The KVM refused or did not keep the certificate: a ``setTLSState`` error, or mode not ``custom`` (exit 6)."""


class ProtocolError(DeviceError):
    """Bad replies, timeouts and network failures (exit 8)."""


class RpcError(ProtocolError):
    """The KVM answered an RPC call with a JSON-RPC error."""


def _strip_queries(text: str) -> str:
    """Drop ``?query`` parts of URLs: the signalling URL carries the CSRF token."""
    return re.sub(r"(https?|wss?)://[^\s'\"]*", lambda m: m.group(0).split("?", 1)[0], text)


@contextlib.contextmanager
def _network_errors() -> Iterator[None]:
    """Report transport failures as ``ProtocolError``; typed device errors pass through.

    A connection refused because the KVM's certificate fails verification or doesn't match the pin is an
    identity failure (exit 4), like the same failure caught earlier by ``choose_trust``: it can happen here if
    the certificate changes in between, or something answers this connection with a different one.
    """
    try:
        yield
    except DeviceError:
        raise
    except (aiohttp.ServerFingerprintMismatch, aiohttp.ClientConnectorCertificateError) as exc:
        raise IdentityError(
            f"the KVM's certificate no longer passed verification (or the pin) when connecting, so nothing was "
            f"sent: {type(exc).__name__}: {_strip_queries(str(exc))}"
        ) from None
    except (aiohttp.ClientError, OSError, TimeoutError) as exc:
        text = _strip_queries(str(exc))
        # from None: the original exception's text can carry the signalling URL's CSRF token, and -v prints
        # the whole traceback, chained causes included.
        raise ProtocolError(f"{type(exc).__name__}: {text}" if text else type(exc).__name__) from None


async def _refuse_redirect(
    session: aiohttp.ClientSession, ctx: object, params: aiohttp.TraceRequestRedirectParams
) -> None:
    """Never follow a redirect. aiohttp's ``ws_connect`` follows them and has no option to stop it, and a
    redirect to another host with a valid certificate would hand it the CSRF token and the WebRTC session
    (and so the private key)."""
    location = params.response.headers.get("Location", "").split("?", 1)[0]  # may be relative
    params.response.close()  # aiohttp abandons the redirect response when this raises; don't leak its socket
    raise ProtocolError(f"the KVM redirected {params.url.with_query(None)} to {location or '?'}; refusing")


def _redirect_guard() -> aiohttp.TraceConfig:
    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(_refuse_redirect)
    return trace


async def wait_for_ice_gathering(pc: RTCPeerConnection, timeout: float) -> None:
    if pc.iceGatheringState == "complete":
        return
    complete = asyncio.Event()

    @pc.on("icegatheringstatechange")
    async def on_state_change() -> None:
        if pc.iceGatheringState == "complete":
            complete.set()

    await asyncio.wait_for(complete.wait(), timeout)


async def checked_json(response: aiohttp.ClientResponse) -> Any:
    text = await response.text()
    if response.status >= 400:
        try:
            detail = json.loads(text)
        except json.JSONDecodeError:
            detail = text.strip() or response.reason
        raise ProtocolError(f"HTTP {response.status} from {response.url}: {detail}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"non-JSON response from {response.url}") from exc


async def login(session: aiohttp.ClientSession, base_url: str, password: str) -> str:
    """Log in with the local password; return the CSRF token. Redirects are never followed."""
    headers = {"Origin": base_url, "Referer": base_url + "/"}
    async with session.post(
        base_url + "/auth/login-local",
        json={"password": password},
        headers=headers,
        allow_redirects=False,
    ) as response:
        if response.status in (401, 403):
            raise LoginError(f"the KVM rejected the login (HTTP {response.status})")
        if 300 <= response.status < 400:
            raise ProtocolError(f"unexpected redirect (HTTP {response.status}) from {response.url}")
        body = await checked_json(response)
        csrf = response.headers.get("X-CSRF-Token") or (body.get("csrfToken") if isinstance(body, dict) else None)
        if not csrf:
            raise ProtocolError("login succeeded but the device returned no CSRF token")
        return str(csrf)


async def rpc_call(
    channel: Any,
    pending: dict[int, asyncio.Future[Any]],
    method: str,
    params: dict[str, Any] | None,
    request_id: int,
    timeout: float,
) -> Any:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[Any] = loop.create_future()
    pending[request_id] = future
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": request_id}
    if params is not None:
        message["params"] = params
    channel.send(json.dumps(message))
    try:
        response = await asyncio.wait_for(future, timeout)
    except TimeoutError:
        raise ProtocolError(f"timed out after {timeout:g}s waiting for the {method} reply") from None
    finally:
        pending.pop(request_id, None)
    if "error" in response:
        error = response["error"]
        detail = (error.get("data") or error.get("message") or error) if isinstance(error, dict) else error
        raise RpcError(f"{method} failed: {detail}")
    return response.get("result")


def signaling_url(base_url: str, csrf: str) -> str:
    parsed = urlsplit(base_url)
    path = parsed.path + "/webrtc/signaling/client"
    return urlunsplit(("wss", parsed.netloc, path, urlencode({"csrf-token": csrf}), ""))


async def add_remote_candidate(pc: RTCPeerConnection, data: Any) -> None:
    if not isinstance(data, dict) or not data.get("candidate"):
        return
    try:
        candidate = candidate_from_sdp(str(data["candidate"]).removeprefix("candidate:"))
        candidate.sdpMid = data.get("sdpMid")
        candidate.sdpMLineIndex = data.get("sdpMLineIndex")
        await pc.addIceCandidate(candidate)
    except (AssertionError, ValueError, TypeError, AttributeError) as exc:
        raise ProtocolError(f"device sent a malformed ICE candidate: {exc or type(exc).__name__}") from exc


async def receive_signal(ws: aiohttp.ClientWebSocketResponse, timeout: float) -> dict[str, Any] | None:
    msg = await ws.receive(timeout=timeout)
    if msg.type in (
        aiohttp.WSMsgType.CLOSE,
        aiohttp.WSMsgType.CLOSING,
        aiohttp.WSMsgType.CLOSED,
        aiohttp.WSMsgType.ERROR,
    ):
        raise ProtocolError("device closed the signalling connection")
    if msg.type != aiohttp.WSMsgType.TEXT or msg.data == "pong":
        return None
    try:
        data = json.loads(msg.data)
    except json.JSONDecodeError:
        LOG.warning("ignoring malformed signalling message")
        return None
    if not isinstance(data, dict):
        LOG.warning("ignoring non-dict signalling message")
        return None
    return data


async def wait_for_signal(
    ws: aiohttp.ClientWebSocketResponse,
    kind: str,
    timeout: float,
    candidates: list[Any],
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    message = f"timed out after {timeout:g}s waiting for {kind!r} from the device"
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise ProtocolError(message)
        try:
            msg = await receive_signal(ws, remaining)
        except TimeoutError:
            raise ProtocolError(message) from None
        if msg is None:
            continue
        if msg.get("type") == kind:
            return msg
        if msg.get("type") == "new-ice-candidate":
            candidates.append(msg.get("data"))


async def relay_ice_candidates(
    ws: aiohttp.ClientWebSocketResponse,
    pc: RTCPeerConnection,
    interval: float = 0.5,
) -> None:
    # The device only flushes its queued ICE candidates after it receives a message.
    try:
        await ws.send_str("ping")
        while True:
            try:
                message = await receive_signal(ws, interval)
            except TimeoutError:
                await ws.send_str("ping")
                continue
            if message and message.get("type") == "new-ice-candidate":
                try:
                    await add_remote_candidate(pc, message.get("data"))
                except ProtocolError as exc:
                    LOG.warning("ignoring ICE candidate: %s", exc)
    except (ProtocolError, aiohttp.ClientError, ConnectionResetError):
        return


@contextlib.asynccontextmanager
async def _logged_in_session(
    base_url: str, password: str, *, trust: Trust, timeout: float
) -> AsyncIterator[tuple[aiohttp.ClientSession, str]]:
    """An HTTP session that trusts the KVM as ``trust`` says, already logged in; yields (session, csrf token)."""
    connector = aiohttp.TCPConnector(ssl=aiohttp_ssl(trust))
    headers = {"Accept": "application/json", "User-Agent": f"arkkvm-cert-updater/{version('arkkvm-cert-updater')}"}
    async with aiohttp.ClientSession(
        connector=connector,
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers=headers,
        trace_configs=[_redirect_guard()],
    ) as session:
        yield session, await login(session, base_url, password)


async def check_login(base_url: str, password: str, *, trust: Trust, timeout: float) -> None:
    """Log in and nothing else (no WebRTC). Raises ``LoginError`` if the password is rejected."""
    with _network_errors():
        async with _logged_in_session(base_url, password, trust=trust, timeout=timeout):
            pass


async def install_certificate(
    base_url: str, password: str, certs_pem: str, key_pem: str, *, trust: Trust, timeout: float
) -> None:
    """Install ``certs_pem``/``key_pem`` in custom mode, verify the KVM kept it, and reboot the KVM."""
    pc = RTCPeerConnection()
    try:
        with _network_errors():
            async with _logged_in_session(base_url, password, trust=trust, timeout=timeout) as (session, csrf):
                await _install(pc, session, base_url, csrf, certs_pem, key_pem, timeout)
    finally:
        await pc.close()


async def _install(
    pc: RTCPeerConnection,
    session: aiohttp.ClientSession,
    base_url: str,
    csrf: str,
    certs_pem: str,
    key_pem: str,
    timeout: float,
) -> None:
    channel = pc.createDataChannel("rpc", ordered=True)
    opened = asyncio.Event()
    pending: dict[int, asyncio.Future[Any]] = {}

    @channel.on("open")
    def on_open() -> None:
        opened.set()

    @channel.on("message")
    def on_message(message: Any) -> None:
        try:
            data = json.loads(message.decode("utf-8") if isinstance(message, bytes) else message)
            future = pending.get(data.get("id"))
            if future and not future.done():
                future.set_result(data)
        except Exception as exc:
            LOG.warning("ignored malformed RPC response: %s", exc)

    # Closing this socket closes the device's WebRTC session, so it stays open for the whole update.
    async with session.ws_connect(signaling_url(base_url, csrf), headers={"Origin": base_url}) as ws:
        candidates: list[Any] = []
        await wait_for_signal(ws, "device-metadata", timeout, candidates)

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        await wait_for_ice_gathering(pc, timeout)
        local = pc.localDescription
        if local is None:
            raise ProtocolError("WebRTC did not produce a local offer")
        encoded_offer = base64.b64encode(json.dumps({"sdp": local.sdp, "type": local.type}).encode()).decode()

        await ws.send_json({"type": "offer", "data": {"sd": encoded_offer}})
        reply = await wait_for_signal(ws, "answer", timeout, candidates)
        try:
            answer_data = json.loads(base64.b64decode(reply["data"], validate=True))
            answer = RTCSessionDescription(sdp=answer_data["sdp"], type=answer_data["type"])
            await pc.setRemoteDescription(answer)
        except (KeyError, ValueError, TypeError, AssertionError, AttributeError) as exc:
            raise ProtocolError("device returned an invalid WebRTC answer") from exc

        for data in candidates:
            await add_remote_candidate(pc, data)

        relay = asyncio.create_task(relay_ice_candidates(ws, pc))
        try:
            try:
                await asyncio.wait_for(opened.wait(), timeout)
            except TimeoutError:
                raise ProtocolError(
                    f"timed out after {timeout:g}s waiting for the WebRTC data channel to open"
                ) from None

            state = {"mode": "custom", "certificate": certs_pem, "privateKey": key_pem}
            try:
                await rpc_call(channel, pending, "setTLSState", {"state": state}, 1, timeout)
            except RpcError as exc:
                raise RefusedError(str(exc)) from exc
            current = await rpc_call(channel, pending, "getTLSState", None, 2, timeout)
            if not isinstance(current, dict) or current.get("mode") != "custom":
                # Report only the mode: the reply might echo the certificate or private key.
                mode = current.get("mode") if isinstance(current, dict) else type(current).__name__
                raise RefusedError(f"verification failed; the device reports TLS mode {mode!r}, not 'custom'")
            LOG.info("TLS state saved; rebooting the KVM to activate it")

            # A reboot may tear down the channel before its response arrives.
            with contextlib.suppress(DeviceError, TimeoutError):
                await rpc_call(channel, pending, "reboot", {"force": True}, 3, min(timeout, 5))
        finally:
            relay.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await relay
