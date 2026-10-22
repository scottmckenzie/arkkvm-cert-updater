#!/usr/bin/env python3
"""Update an ArkKVM device's TLS mode/certificate through its public API."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import getpass
import json
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

try:
    import aiohttp
    from aiortc import RTCSessionDescription, RTCPeerConnection
    from aiortc.sdp import candidate_from_sdp
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError as exc:
    print(
        "Missing dependency. Install with:\n"
        "  uv tool install .",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

LOG = logging.getLogger("arkkvm-cert-updater")

class ArkKVMError(RuntimeError):
    """A device, protocol, or validation error."""

def normalise_base_url(value: str) -> str:
    if "://" not in value:
        value = "http://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise argparse.ArgumentTypeError("device must be a hostname/IP or an http(s) URL")
    if parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("device URL must not contain a query or fragment")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))

def load_custom_material(cert_path: Path, key_path: Path) -> tuple[str, str]:
    try:
        certificate = cert_path.read_text(encoding="utf-8").strip()
        private_key = key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ArkKVMError(f"could not read certificate material: {exc}") from exc

    if "-----BEGIN CERTIFICATE-----" not in certificate:
        raise ArkKVMError(f"{cert_path} does not contain a PEM certificate")
    if "-----BEGIN" not in private_key or "PRIVATE KEY-----" not in private_key:
        raise ArkKVMError(f"{key_path} does not contain a PEM private key")

    try:
        leaf_block = (
            certificate.split("-----END CERTIFICATE-----", 1)[0]
            + "-----END CERTIFICATE-----\n"
        )
        leaf = x509.load_pem_x509_certificate(leaf_block.encode())
        key = serialization.load_pem_private_key(private_key.encode(), password=None)
        cert_public = leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (ValueError, TypeError) as exc:
        raise ArkKVMError(f"invalid or encrypted PEM material: {exc}") from exc
    if cert_public != key_public:
        raise ArkKVMError("certificate and private key do not match")
    return certificate + "\n", private_key + "\n"

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
        raise ArkKVMError(f"HTTP {response.status} from {response.url}: {detail}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArkKVMError(f"non-JSON response from {response.url}") from exc

async def login(
    session: aiohttp.ClientSession, base_url: str, password: str | None
) -> str | None:
    if password is None:
        return None
    headers = {"Origin": base_url, "Referer": base_url + "/"}
    async with session.post(
        base_url + "/auth/login-local",
        json={"password": password},
        headers=headers,
    ) as response:
        body = await checked_json(response)
        csrf = response.headers.get("X-CSRF-Token") or body.get("csrfToken")
        if not csrf:
            raise ArkKVMError("login succeeded but the device returned no CSRF token")
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
    finally:
        pending.pop(request_id, None)
    if "error" in response:
        error = response["error"]
        detail = error.get("data") or error.get("message") or error
        raise ArkKVMError(f"{method} failed: {detail}")
    return response.get("result")

def signaling_url(base_url: str, csrf: str | None) -> str:
    parsed = urlsplit(base_url)
    scheme = "ws" if parsed.scheme == "http" else "wss"
    path = parsed.path + "/webrtc/signaling/client"
    query = urlencode({"csrf-token": csrf}) if csrf else ""
    return urlunsplit((scheme, parsed.netloc, path, query, ""))

async def add_remote_candidate(pc: RTCPeerConnection, data: Any) -> None:
    if not isinstance(data, dict) or not data.get("candidate"):
        return
    cand_str = data["candidate"].removeprefix("candidate:")
    candidate = candidate_from_sdp(cand_str)
    candidate.sdpMid = data.get("sdpMid")
    candidate.sdpMLineIndex = data.get("sdpMLineIndex")
    await pc.addIceCandidate(candidate)

async def receive_signal(
    ws: aiohttp.ClientWebSocketResponse, timeout: float
) -> dict[str, Any] | None:
    msg = await ws.receive(timeout=timeout)
    if msg.type in (
        aiohttp.WSMsgType.CLOSE,
        aiohttp.WSMsgType.CLOSING,
        aiohttp.WSMsgType.CLOSED,
        aiohttp.WSMsgType.ERROR,
    ):
        raise ArkKVMError("device closed the signalling connection")
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
            raise ArkKVMError(message)
        try:
            msg = await receive_signal(ws, remaining)
        except asyncio.TimeoutError:
            raise ArkKVMError(message) from None
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
            except asyncio.TimeoutError:
                await ws.send_str("ping")
                continue
            if message and message.get("type") == "new-ice-candidate":
                await add_remote_candidate(pc, message.get("data"))
    except (ArkKVMError, aiohttp.ClientError, ConnectionResetError):
        return

async def update_device(args: argparse.Namespace) -> None:
    ssl_context: ssl.SSLContext | bool
    if args.insecure:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    else:
        ssl_context = ssl.create_default_context(cafile=args.ca_file)

    connector = aiohttp.TCPConnector(ssl=ssl_context)
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    headers = {"Accept": "application/json", "User-Agent": "arkkvm-update-cert/1.0"}
    pc = RTCPeerConnection()
    channel = pc.createDataChannel("rpc", ordered=True)
    opened = asyncio.Event()
    pending: dict[int, asyncio.Future[Any]] = {}

    @channel.on("open")
    def on_open() -> None:
        opened.set()

    @channel.on("message")
    def on_message(message: Any) -> None:
        try:
            data = json.loads(
                message.decode("utf-8") if isinstance(message, bytes) else message
            )
            request_id = data.get("id")
            future = pending.get(request_id)
            if future and not future.done():
                future.set_result(data)
        except Exception as exc:
            LOG.warning("ignored malformed RPC response: %s", exc)

    try:
        async with aiohttp.ClientSession(
            connector=connector, cookie_jar=cookie_jar, timeout=timeout, headers=headers
        ) as session:
            csrf = await login(session, args.device, args.password)
            # Closing this socket closes the device's WebRTC session, so it stays open
            # for the whole update.
            async with session.ws_connect(
                signaling_url(args.device, csrf), headers={"Origin": args.device}
            ) as ws:
                candidates: list[Any] = []
                await wait_for_signal(ws, "device-metadata", args.timeout, candidates)

                offer = await pc.createOffer()
                await pc.setLocalDescription(offer)
                await wait_for_ice_gathering(pc, args.timeout)
                local = pc.localDescription
                if local is None:
                    raise ArkKVMError("WebRTC did not produce a local offer")
                encoded_offer = base64.b64encode(
                    json.dumps({"sdp": local.sdp, "type": local.type}).encode()
                ).decode()

                await ws.send_json({"type": "offer", "data": {"sd": encoded_offer}})
                reply = await wait_for_signal(ws, "answer", args.timeout, candidates)
                try:
                    answer_data = json.loads(
                        base64.b64decode(reply["data"], validate=True)
                    )
                    answer = RTCSessionDescription(
                        sdp=answer_data["sdp"], type=answer_data["type"]
                    )
                except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                    raise ArkKVMError("device returned an invalid WebRTC answer") from exc
                await pc.setRemoteDescription(answer)

                for data in candidates:
                    await add_remote_candidate(pc, data)

                relay = asyncio.create_task(relay_ice_candidates(ws, pc))
                try:
                    try:
                        await asyncio.wait_for(opened.wait(), args.timeout)
                    except asyncio.TimeoutError:
                        raise ArkKVMError(
                            f"timed out after {args.timeout:g}s waiting for the "
                            "WebRTC data channel to open"
                        ) from None

                    if args.mode == "custom":
                        certificate, private_key = load_custom_material(args.cert, args.key)
                        state = {
                            "mode": "custom",
                            "certificate": certificate,
                            "privateKey": private_key,
                        }
                    else:
                        state = {"mode": args.mode}

                    await rpc_call(
                        channel, pending, "setTLSState", {"state": state}, 1, args.timeout
                    )
                    current = await rpc_call(
                        channel, pending, "getTLSState", None, 2, args.timeout
                    )
                    if not isinstance(current, dict) or current.get("mode") != args.mode:
                        raise ArkKVMError(
                            f"verification failed; device returned TLS state {current!r}"
                        )
                    print(f"TLS mode successfully updated to {args.mode!r}.")

                    if args.reboot:
                        print(
                            "Rebooting ArkKVM to activate the new listener configuration..."
                        )
                        try:
                            await rpc_call(
                                channel,
                                pending,
                                "reboot",
                                {"force": True},
                                3,
                                min(args.timeout, 5),
                            )
                        except (ArkKVMError, asyncio.TimeoutError):
                            # A reboot may tear down the channel before its response arrives.
                            pass
                    else:
                        print("Reboot the ArkKVM to activate the new TLS configuration.")
                finally:
                    relay.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await relay
    finally:
        await pc.close()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Update an ArkKVM TLS certificate through its WebRTC JSON-RPC API."
    )
    parser.add_argument("device", type=normalise_base_url, help="device URL or host/IP")
    parser.add_argument(
        "--mode",
        choices=("custom", "self-signed", "disabled"),
        default="custom",
        help="TLS mode to apply (default: custom)",
    )
    parser.add_argument("--cert", type=Path, help="PEM leaf certificate or chain")
    parser.add_argument("--key", type=Path, help="matching unencrypted PEM private key")
    parser.add_argument(
        "--password",
        help=(
            "local device password (default: ARKKVM_PASSWORD, then a hidden prompt; "
            "use --no-password if auth is disabled)"
        ),
    )
    parser.add_argument(
        "--no-password", action="store_true", help="device uses noPassword mode"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify the device's current HTTPS certificate",
    )
    parser.add_argument("--ca-file", help="CA bundle for the device's current HTTPS certificate")
    parser.add_argument("--timeout", type=float, default=20.0, help="timeout in seconds")
    parser.add_argument(
        "--reboot", action="store_true", help="reboot after verifying the saved TLS state"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.mode == "custom" and (not args.cert or not args.key):
        parser.error("--cert and --key are required with --mode custom")
    if args.mode != "custom" and (args.cert or args.key):
        parser.error("--cert and --key are only valid with --mode custom")
    if args.no_password and args.password is not None:
        parser.error("--password and --no-password are mutually exclusive")
    if args.insecure and args.ca_file:
        parser.error("--insecure and --ca-file are mutually exclusive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not args.no_password and args.password is None:
        args.password = os.environ.get("ARKKVM_PASSWORD")
        if args.password is None:
            args.password = getpass.getpass("ArkKVM password: ")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        asyncio.run(update_device(args))
    except (ArkKVMError, asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
        print(f"Error: {str(exc) or type(exc).__name__}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
