import asyncio
import base64
import json
import ssl
import types
from typing import Any

import aiohttp
import pytest

from arkkvm_cert_updater import device as _device
from arkkvm_cert_updater.tls import Trust

m: Any = _device  # the unit tests pass fakes where the real aiohttp/aiortc types are expected
BASE = "https://dev"
TRUST = Trust(ssl.create_default_context(), None)

# Fakes for the unit tests of the small helpers -----------------------------


class FakeResponse:
    def __init__(self, status=200, text="", headers=None, reason="OK", url="https://dev/x"):
        self.status = status
        self._text = text
        self.headers = headers or {}
        self.reason = reason
        self.url = url

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, json=None, headers=None, allow_redirects=True):
        self.calls.append((url, json, headers, allow_redirects))
        return self.response


class FakeChannel:
    def __init__(self, pending, reply):
        self.pending = pending
        self.reply = reply
        self.sent = []

    def send(self, text):
        decoded = json.loads(text)
        self.sent.append(decoded)
        if self.reply is not None:
            loop = asyncio.get_running_loop()
            loop.call_soon(self._set_reply, decoded["id"])

    def _set_reply(self, request_id):
        future = self.pending.get(request_id)
        if future:
            future.set_result(self.reply)


class FakePC:
    def __init__(self, state):
        self.iceGatheringState = state
        self.handlers = {}

    def on(self, event):
        def decorator(func):
            self.handlers[event] = func
            return func

        return decorator


def test_checked_json_success():
    resp = FakeResponse(status=200, text='{"a": 1}')
    assert asyncio.run(m.checked_json(resp)) == {"a": 1}


def test_checked_json_401_with_json_body():
    resp = FakeResponse(status=401, text='{"error":"bad"}', reason="Unauthorized")
    with pytest.raises(m.ProtocolError) as exc:
        asyncio.run(m.checked_json(resp))
    assert "HTTP 401" in str(exc.value)
    assert "bad" in str(exc.value)


def test_checked_json_500_empty_text():
    resp = FakeResponse(status=500, text="", reason="Server Error")
    with pytest.raises(m.ProtocolError, match="Server Error"):
        asyncio.run(m.checked_json(resp))


def test_checked_json_non_json_body():
    with pytest.raises(m.ProtocolError, match="non-JSON response"):
        asyncio.run(m.checked_json(FakeResponse(status=200, text="not json")))


def test_login_header_csrf_token():
    session = FakeSession(FakeResponse(text="{}", headers={"X-CSRF-Token": "hdr"}))
    assert asyncio.run(m.login(session, BASE, "pw")) == "hdr"
    assert session.calls == [
        ("https://dev/auth/login-local", {"password": "pw"}, {"Origin": BASE, "Referer": BASE + "/"}, False)
    ]


def test_login_body_csrf_token():
    session = FakeSession(FakeResponse(text='{"csrfToken":"body-token"}'))
    assert asyncio.run(m.login(session, BASE, "pw")) == "body-token"


def test_login_no_csrf_token():
    session = FakeSession(FakeResponse(text="{}"))
    with pytest.raises(m.ProtocolError, match="no CSRF token"):
        asyncio.run(m.login(session, BASE, "pw"))


@pytest.mark.parametrize("status", [401, 403])
def test_login_rejected_raises_login_error(status):
    session = FakeSession(FakeResponse(status=status, text='{"error":"nope"}'))
    with pytest.raises(m.LoginError):
        asyncio.run(m.login(session, BASE, "pw"))


def test_login_redirect_is_protocol_error():
    session = FakeSession(FakeResponse(status=302, text="", headers={"Location": "https://evil/"}))
    with pytest.raises(m.ProtocolError, match="redirect"):
        asyncio.run(m.login(session, BASE, "pw"))


def test_rpc_call_success():
    pending = {}
    channel = FakeChannel(pending, {"id": 7, "result": {"mode": "custom"}})
    result = asyncio.run(m.rpc_call(channel, pending, "getTLSState", None, 7, 1))
    assert result == {"mode": "custom"}
    assert pending == {}
    assert channel.sent[0] == {"jsonrpc": "2.0", "method": "getTLSState", "id": 7}


def test_rpc_call_with_params():
    pending = {}
    channel = FakeChannel(pending, {"id": 1, "result": {}})
    params = {"state": {"mode": "custom"}}
    assert asyncio.run(m.rpc_call(channel, pending, "setTLSState", params, 1, 1)) == {}
    assert channel.sent[0]["params"] == params


def test_rpc_call_error_with_data():
    pending = {}
    channel = FakeChannel(pending, {"id": 1, "error": {"code": -1, "message": "msg", "data": "detail"}})
    with pytest.raises(m.ProtocolError, match="setTLSState failed: detail"):
        asyncio.run(m.rpc_call(channel, pending, "setTLSState", None, 1, 1))
    assert pending == {}


def test_rpc_call_error_with_message():
    pending = {}
    channel = FakeChannel(pending, {"id": 1, "error": {"message": "msg"}})
    with pytest.raises(m.ProtocolError, match="failed: msg"):
        asyncio.run(m.rpc_call(channel, pending, "setTLSState", None, 1, 1))
    assert pending == {}


def test_rpc_call_timeout():
    pending = {}
    channel = FakeChannel(pending, None)
    with pytest.raises(TimeoutError):
        asyncio.run(m.rpc_call(channel, pending, "getTLSState", None, 1, 0.01))
    assert pending == {}


def test_wait_for_ice_gathering_complete():
    asyncio.run(m.wait_for_ice_gathering(FakePC("complete"), 1))


def test_wait_for_ice_gathering_waits_and_completes():
    async def inner():
        pc = FakePC("gathering")
        task = asyncio.create_task(m.wait_for_ice_gathering(pc, 1))
        await asyncio.sleep(0)
        pc.iceGatheringState = "complete"
        await pc.handlers["icegatheringstatechange"]()
        await task

    asyncio.run(inner())


def test_wait_for_ice_gathering_timeout():
    async def inner():
        with pytest.raises(TimeoutError):
            await m.wait_for_ice_gathering(FakePC("gathering"), 0.01)

    asyncio.run(inner())


def test_signaling_url_https_only():
    assert (
        m.signaling_url("https://kvm.example.com", "t") == "wss://kvm.example.com/webrtc/signaling/client?csrf-token=t"
    )
    assert m.signaling_url("https://dev:8443", "a b") == "wss://dev:8443/webrtc/signaling/client?csrf-token=a+b"


def test_add_remote_candidate_ignores_empty():
    calls = []

    class Pc:
        async def addIceCandidate(self, candidate):
            calls.append(candidate)

    asyncio.run(m.add_remote_candidate(Pc(), None))
    asyncio.run(m.add_remote_candidate(Pc(), {"candidate": ""}))
    assert calls == []


def test_receive_signal_closed():
    class FakeWS:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.CLOSED, None, None)

    with pytest.raises(m.ProtocolError, match="closed the signalling connection"):
        asyncio.run(m.receive_signal(FakeWS(), timeout=1))


def test_receive_signal_non_dict_and_binary():
    class TextWS:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "[1]", None)

    class BinaryWS:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, b"x", None)

    assert asyncio.run(m.receive_signal(TextWS(), timeout=1)) is None
    assert asyncio.run(m.receive_signal(BinaryWS(), timeout=1)) is None


def test_relay_stops_on_close():
    class FakeWS:
        def __init__(self):
            self.sent_str = []
            self.responses = [TimeoutError(), aiohttp.WSMessage(aiohttp.WSMsgType.CLOSED, None, None)]

        async def send_str(self, data):
            self.sent_str.append(data)

        async def receive(self, timeout=None):
            r = self.responses.pop(0)
            if isinstance(r, BaseException):
                raise r
            return r

    ws = FakeWS()
    asyncio.run(m.relay_ice_candidates(ws, object(), interval=0.01))
    assert ws.sent_str == ["ping", "ping"]


# Full-flow tests against a faked device ------------------------------------


def good_answer_sd():
    return base64.b64encode(json.dumps({"sdp": "v=0 answer", "type": "answer"}).encode()).decode()


@pytest.fixture
def device(monkeypatch):
    class Device:
        def __init__(self):
            self.replies = {
                "setTLSState": {"result": None},
                "getTLSState": {"result": {"mode": "custom"}},
            }
            self.sent = []
            self.remote = None
            self.closed = False
            self.no_local = False
            self.answer_sd = good_answer_sd()
            self.session = None
            self.connector_ssl = None
            self.session_kwargs = None
            self.ws = None
            self.pcs = []
            self.candidates = []
            self.added = []
            self.open_channel = True
            self.send_metadata = True
            self.login_status = 200
            self.login_exc = None

    dev = Device()

    class FakeResponse:
        def __init__(self, body, headers=None, status=200):
            self.body = body
            self.status = status
            self.headers = headers or {}
            self.reason = "OK"
            self.url = "https://dev"

        async def text(self):
            return self.body if isinstance(self.body, str) else json.dumps(self.body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        def __init__(self):
            self.posts = []

        def post(self, url, json=None, headers=None, allow_redirects=True):
            self.posts.append((url, json, headers, allow_redirects))
            if dev.login_exc is not None:
                raise dev.login_exc
            return FakeResponse({}, headers={"X-CSRF-Token": "tok"}, status=dev.login_status)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def ws_connect(self, url, headers=None):
            ws = FakeWebSocket(dev, url, headers)
            dev.ws = ws
            return ws

    class FakeDescription:
        def __init__(self, sdp, type):
            self.sdp = sdp
            self.type = type

    class FakeChannel:
        def __init__(self, device):
            self.device = device
            self.handlers = {}

        def on(self, event):
            def decorator(fn):
                self.handlers[event] = fn
                return fn

            return decorator

        def send(self, text):
            msg = json.loads(text.decode("utf-8") if isinstance(text, bytes) else text)
            self.device.sent.append(msg)
            reply = self.device.replies.get(msg["method"])
            if reply is not None:
                loop = asyncio.get_running_loop()
                loop.call_soon(self.handlers["message"], b"not json")
                loop.call_soon(self.handlers["message"], json.dumps({"id": msg["id"], **reply}).encode())

    class FakePC:
        def __init__(self, device):
            self.device = device
            self.iceGatheringState = "complete"
            self.localDescription = None
            self.closed = False
            self.channel = FakeChannel(device)

        def createDataChannel(self, label, ordered=True):
            return self.channel

        async def createOffer(self):
            return FakeDescription("v=0 offer", "offer")

        async def setLocalDescription(self, desc):
            if not self.device.no_local:
                self.localDescription = desc

        async def setRemoteDescription(self, desc):
            self.device.remote = desc
            if self.device.open_channel:
                self.channel.handlers["open"]()

        async def addIceCandidate(self, candidate):
            self.device.added.append(candidate)

        async def close(self):
            self.closed = True
            self.device.closed = True

    class FakeWebSocket:
        def __init__(self, device, url, headers):
            self.device = device
            self.url = url
            self.headers = headers or {}
            self.sent_json = []
            self.sent_str = []
            self.queue = asyncio.Queue()

        async def __aenter__(self):
            if self.device.send_metadata:
                await self.queue.put(
                    aiohttp.WSMessage(
                        aiohttp.WSMsgType.TEXT, '{"type":"device-metadata","data":{"deviceVersion":"1"}}', None
                    )
                )
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def send_json(self, data):
            self.sent_json.append(data)
            if data["type"] == "offer":
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "pong", None))
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "not json", None))
                answer = json.dumps({"type": "answer", "data": self.device.answer_sd})
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, answer, None))
                for c in self.device.candidates:
                    cand = json.dumps({"type": "new-ice-candidate", "data": c})
                    await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, cand, None))

        async def send_str(self, data):
            self.sent_str.append(data)
            if data == "ping":
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "pong", None))

        async def receive(self, timeout=None):
            return await asyncio.wait_for(self.queue.get(), timeout)

    def make_pc():
        pc = FakePC(dev)
        dev.pcs.append(pc)
        return pc

    monkeypatch.setattr(m, "RTCPeerConnection", make_pc)
    monkeypatch.setattr(m.aiohttp, "TCPConnector", lambda ssl=None: setattr(dev, "connector_ssl", ssl))

    def fake_client_session(**kwargs):
        dev.session_kwargs = kwargs
        dev.session = FakeSession()
        return dev.session

    monkeypatch.setattr(m.aiohttp, "ClientSession", fake_client_session)

    async def dummy_wait(pc, timeout):
        return None

    monkeypatch.setattr(m, "wait_for_ice_gathering", dummy_wait)
    monkeypatch.setattr(
        m, "candidate_from_sdp", lambda sdp: types.SimpleNamespace(sdp=sdp, sdpMid=None, sdpMLineIndex=None)
    )
    return dev


def install(*, trust=TRUST, timeout=1.0):
    return asyncio.run(m.install_certificate(BASE, "secret", "CERT\n", "KEY\n", trust=trust, timeout=timeout))


def test_install_certificate_flow(device):
    install()
    assert len(device.session.posts) == 1
    assert device.session.posts[0][0] == "https://dev/auth/login-local"
    assert device.ws.url == "wss://dev/webrtc/signaling/client?csrf-token=tok"
    assert device.ws.headers == {"Origin": BASE}
    offer = device.ws.sent_json[0]
    assert offer["type"] == "offer"
    assert json.loads(base64.b64decode(offer["data"]["sd"], validate=True)) == {"sdp": "v=0 offer", "type": "offer"}
    assert device.remote.sdp == "v=0 answer"
    assert [(s["method"], s["id"]) for s in device.sent] == [("setTLSState", 1), ("getTLSState", 2), ("reboot", 3)]
    assert device.sent[0]["params"]["state"] == {"mode": "custom", "certificate": "CERT\n", "privateKey": "KEY\n"}
    assert device.sent[2]["params"] == {"force": True}
    assert device.closed


def test_user_agent_and_cookie_jar(device):
    install()
    headers = device.session_kwargs["headers"]
    assert headers["User-Agent"].startswith("arkkvm-cert-updater/")
    assert device.session_kwargs["cookie_jar"]._unsafe is True


def test_connector_uses_trust(device):
    install()
    assert device.connector_ssl is TRUST.context
    pinned = Trust(TRUST.context, b"\x01" * 32)
    install(trust=pinned)
    assert isinstance(device.connector_ssl, aiohttp.Fingerprint)


def test_login_does_not_follow_redirects(device):
    install()
    assert device.session.posts[0][3] is False


def test_check_login_only_logs_in(device):
    asyncio.run(m.check_login(BASE, "secret", trust=TRUST, timeout=1.0))
    assert len(device.session.posts) == 1
    assert device.ws is None
    assert device.pcs == []


def test_login_401_raises_login_error(device):
    device.login_status = 401
    with pytest.raises(m.LoginError):
        asyncio.run(m.check_login(BASE, "secret", trust=TRUST, timeout=1.0))


def test_login_403_raises_login_error(device):
    device.login_status = 403
    with pytest.raises(m.LoginError):
        install()
    assert device.closed


def test_login_500_raises_protocol_error(device):
    device.login_status = 500
    with pytest.raises(m.ProtocolError) as excinfo:
        asyncio.run(m.check_login(BASE, "secret", trust=TRUST, timeout=1.0))
    assert not isinstance(excinfo.value, m.LoginError)


def test_client_error_wrapped_as_protocol_error(device):
    device.login_exc = aiohttp.ClientConnectionError("boom")
    with pytest.raises(m.ProtocolError, match="boom"):
        asyncio.run(m.check_login(BASE, "secret", trust=TRUST, timeout=1.0))


def test_os_error_wrapped_as_protocol_error(device):
    device.login_exc = ConnectionRefusedError()
    with pytest.raises(m.ProtocolError, match="ConnectionRefusedError"):
        install()


def test_set_tls_state_error_raises_refused(device):
    device.replies["setTLSState"] = {"error": {"message": "bad key"}}
    with pytest.raises(m.RefusedError, match="bad key"):
        install()
    assert [s["method"] for s in device.sent] == ["setTLSState"]


def test_verification_mismatch_raises_refused(device):
    device.replies["getTLSState"]["result"] = {"mode": "self-signed"}
    with pytest.raises(m.RefusedError, match="verification failed"):
        install()
    assert device.closed
    assert "reboot" not in [s["method"] for s in device.sent]


def test_reboot_without_reply_is_ok(device):
    install(timeout=0.05)
    assert device.sent[-1]["method"] == "reboot"
    assert device.sent[-1]["params"] == {"force": True}


def test_reboot_with_error_is_ok(device):
    device.replies["reboot"] = {"error": {"message": "bye"}}
    install(timeout=0.05)
    assert device.sent[-1]["method"] == "reboot"


def test_invalid_answer(device):
    device.answer_sd = "!!!"
    with pytest.raises(m.ProtocolError, match="invalid WebRTC answer"):
        install()
    assert device.closed


def test_no_local_description(device):
    device.no_local = True
    with pytest.raises(m.ProtocolError, match="did not produce a local offer"):
        install()
    assert device.closed


def test_candidates_relayed(device):
    device.candidates = [{"candidate": "candidate:1 1 udp 1 10.0.0.2 5000 typ host", "sdpMid": "0", "sdpMLineIndex": 0}]
    device.open_channel = False
    with pytest.raises(m.ProtocolError, match="waiting for the WebRTC data channel to open"):
        install(timeout=0.3)
    assert len(device.added) == 1
    cand = device.added[0]
    assert cand.sdp == "1 1 udp 1 10.0.0.2 5000 typ host"
    assert cand.sdpMid == "0"
    assert cand.sdpMLineIndex == 0
    assert "ping" in device.ws.sent_str


def test_metadata_timeout(device):
    device.send_metadata = False
    with pytest.raises(m.ProtocolError, match="waiting for 'device-metadata'"):
        install(timeout=0.05)
    assert device.closed
