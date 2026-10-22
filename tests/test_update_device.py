import argparse
import asyncio
import base64
import json
import ssl
import sys
import types

import aiohttp
import pytest

import arkkvm_update_cert as m


def make_args(**overrides):
    defaults = dict(
        device="http://dev",
        mode="disabled",
        cert=None,
        key=None,
        password=None,
        insecure=False,
        ca_file=None,
        timeout=1.0,
        reboot=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def good_answer_sd():
    return base64.b64encode(
        json.dumps({"sdp": "v=0 answer", "type": "answer"}).encode()
    ).decode()


@pytest.fixture
def device(monkeypatch):
    class Device:
        def __init__(self):
            self.replies = {
                "setTLSState": {"result": None},
                "getTLSState": {"result": {"mode": "disabled"}},
            }
            self.sent = []
            self.remote = None
            self.closed = False
            self.no_local = False
            self.answer_sd = good_answer_sd()
            self.session = None
            self.connector_ssl = None
            self.ws = None
            self.candidates = []
            self.added = []
            self.open_channel = True
            self.send_metadata = True

    dev = Device()

    class FakeResponse:
        def __init__(self, body, headers=None, status=200):
            self.body = body
            self.status = status
            self.headers = headers or {}
            self.reason = "OK"
            self.url = "http://dev"

        async def text(self):
            if isinstance(self.body, str):
                return self.body
            return json.dumps(self.body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        def __init__(self, answer_sd):
            self.answer_sd = answer_sd
            self.posts = []

        def post(self, url, json=None, headers=None):
            self.posts.append((url, json, headers))
            if url.endswith("/auth/login-local"):
                return FakeResponse({}, headers={"X-CSRF-Token": "tok"})
            return FakeResponse({})

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
                loop.call_soon(
                    self.handlers["message"],
                    json.dumps({"id": msg["id"], **reply}).encode(),
                )

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
            self.queue = None

        async def __aenter__(self):
            self.queue = asyncio.Queue()
            if self.device.send_metadata:
                await self.queue.put(
                    aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, '{"type":"device-metadata","data":{"deviceVersion":"1"}}', None)
                )
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def send_json(self, data):
            self.sent_json.append(data)
            if data["type"] == "offer":
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "pong", None))
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "not json", None))
                await self.queue.put(
                    aiohttp.WSMessage(
                        aiohttp.WSMsgType.TEXT,
                        json.dumps({"type": "answer", "data": self.device.answer_sd}),
                        None,
                    )
                )
                for c in self.device.candidates:
                    await self.queue.put(
                        aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, json.dumps({"type":"new-ice-candidate","data":c}), None)
                    )

        async def send_str(self, data):
            self.sent_str.append(data)
            if data == "ping":
                await self.queue.put(aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "pong", None))

        async def receive(self, timeout=None):
            return await asyncio.wait_for(self.queue.get(), timeout)

    monkeypatch.setattr(m, "RTCPeerConnection", lambda: FakePC(dev))
    monkeypatch.setattr(
        m.aiohttp,
        "TCPConnector",
        lambda ssl=None: setattr(dev, "connector_ssl", ssl) or None,
    )
    def fake_client_session(**kwargs):
        dev.session = FakeSession(dev.answer_sd)
        return dev.session
    monkeypatch.setattr(m.aiohttp, "ClientSession", fake_client_session)

    async def dummy_wait(pc, timeout):
        return None
    monkeypatch.setattr(m, "wait_for_ice_gathering", dummy_wait)

    monkeypatch.setattr(m, "candidate_from_sdp", lambda sdp: types.SimpleNamespace(sdp=sdp, sdpMid=None, sdpMLineIndex=None))
    return dev


def test_disabled_mode_no_password_no_reboot(device, capsys):
    args = make_args(mode="disabled", password=None, reboot=False)
    asyncio.run(m.update_device(args))
    out, err = capsys.readouterr()
    assert device.session.posts == []
    assert device.ws.url == "ws://dev/webrtc/signaling/client"
    assert device.ws.headers == {"Origin": "http://dev"}
    offer = device.ws.sent_json[0]
    assert offer["type"] == "offer"
    decoded = json.loads(base64.b64decode(offer["data"]["sd"], validate=True))
    assert decoded == {"sdp": "v=0 offer", "type": "offer"}
    assert device.remote.sdp == "v=0 answer"
    assert device.sent[0]["method"] == "setTLSState"
    assert device.sent[0]["params"]["state"] == {"mode": "disabled"}
    assert device.sent[1]["method"] == "getTLSState"
    assert device.closed
    assert "TLS mode successfully updated to 'disabled'." in out
    assert "Reboot the ArkKVM to activate the new TLS configuration." in out

def test_password_login(device, capsys):
    args = make_args(mode="disabled", password="secret", reboot=False)
    asyncio.run(m.update_device(args))
    out, err = capsys.readouterr()
    assert len(device.session.posts) == 1
    assert device.session.posts[0][0].endswith("/auth/login-local")
    assert device.ws.url == "ws://dev/webrtc/signaling/client?csrf-token=tok"
    assert "TLS mode successfully updated to 'disabled'." in out

def test_invalid_answer(device, capsys):
    device.answer_sd = "!!!"
    args = make_args(mode="disabled", password=None, reboot=False)
    with pytest.raises(m.ArkKVMError) as excinfo:
        asyncio.run(m.update_device(args))
    out, err = capsys.readouterr()
    assert "invalid WebRTC answer" in str(excinfo.value)
    assert device.closed


def test_custom_mode(device, monkeypatch, capsys):
    monkeypatch.setattr(m, "load_custom_material", lambda cert, key: ("CERT\n", "KEY\n"))
    device.replies["getTLSState"]["result"] = {"mode": "custom"}
    args = make_args(mode="custom", cert="c", key="k")
    asyncio.run(m.update_device(args))
    # setTLSState params
    set_call = device.sent[0]
    assert set_call["method"] == "setTLSState"
    state = set_call["params"]["state"]
    assert state["mode"] == "custom"
    assert state["certificate"] == "CERT\n"
    assert state["privateKey"] == "KEY\n"
    # getTLSState called
    assert device.sent[1]["method"] == "getTLSState"


def test_reboot_no_reply(device, capsys):
    args = make_args(reboot=True, timeout=0.05)
    asyncio.run(m.update_device(args))
    out, _ = capsys.readouterr()
    assert "Rebooting ArkKVM to activate the new listener configuration..." in out
    # Last sent method is reboot
    assert device.sent[-1]["method"] == "reboot"
    assert device.sent[-1]["params"] == {"force": True}


def test_reboot_with_error(device, capsys):
    device.replies["reboot"] = {"error": {"message": "bye"}}
    args = make_args(reboot=True, timeout=0.05)
    asyncio.run(m.update_device(args))
    out, _ = capsys.readouterr()
    assert "Rebooting ArkKVM to activate the new listener configuration..." in out


def test_verification_mismatch(device, capsys):
    device.replies["getTLSState"]["result"] = {"mode": "self-signed"}
    args = make_args()
    with pytest.raises(m.ArkKVMError, match="verification failed"):
        asyncio.run(m.update_device(args))
    assert device.closed


def test_no_local_description(device, capsys):
    device.no_local = True
    args = make_args()
    with pytest.raises(m.ArkKVMError, match="did not produce a local offer"):
        asyncio.run(m.update_device(args))
    assert device.closed


def test_insecure_true(device, capsys):
    args = make_args(insecure=True)
    asyncio.run(m.update_device(args))
    ssl_ctx = device.connector_ssl
    assert ssl_ctx.verify_mode == ssl.CERT_NONE
    assert ssl_ctx.check_hostname is False


def test_default_secure(device, capsys):
    args = make_args()
    asyncio.run(m.update_device(args))
    ssl_ctx = device.connector_ssl
    assert ssl_ctx.verify_mode == ssl.CERT_REQUIRED
    assert ssl_ctx.check_hostname is True


def test_signaling_url():
    assert m.signaling_url("http://dev", None) == "ws://dev/webrtc/signaling/client"
    assert m.signaling_url("https://dev/base", "a b") == "wss://dev/base/webrtc/signaling/client?csrf-token=a+b"

def test_candidates_relayed(device, capsys):
    device.candidates = [
        {"candidate": "candidate:1 1 udp 1 10.0.0.2 5000 typ host", "sdpMid": "0", "sdpMLineIndex": 0}
    ]
    device.open_channel = False
    args = make_args(mode="disabled", password=None, reboot=False, timeout=0.3)
    with pytest.raises(m.ArkKVMError) as excinfo:
        asyncio.run(m.update_device(args))
    out, err = capsys.readouterr()
    assert "waiting for the WebRTC data channel to open" in str(excinfo.value)
    assert len(device.added) == 1
    cand = device.added[0]
    assert cand.sdp == "1 1 udp 1 10.0.0.2 5000 typ host"
    assert cand.sdpMid == "0"
    assert cand.sdpMLineIndex == 0
    assert "ping" in device.ws.sent_str

def test_add_remote_candidate_ignores_empty():
    calls = []
    class FakePC:
        async def addIceCandidate(self, candidate):
            calls.append(candidate)
    pc = FakePC()
    asyncio.run(m.add_remote_candidate(pc, None))
    asyncio.run(m.add_remote_candidate(pc, {"candidate": ""}))
    assert calls == []

def test_metadata_timeout(device, capsys):
    device.send_metadata = False
    args = make_args(mode="disabled", password=None, reboot=False, timeout=0.05)
    with pytest.raises(m.ArkKVMError) as excinfo:
        asyncio.run(m.update_device(args))
    out, err = capsys.readouterr()
    assert "waiting for 'device-metadata'" in str(excinfo.value)
    assert device.closed

def test_receive_signal_closed():
    class FakeWS:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.CLOSED, None, None)
    ws = FakeWS()
    with pytest.raises(m.ArkKVMError) as excinfo:
        asyncio.run(m.receive_signal(ws, timeout=1))
    assert "closed the signalling connection" in str(excinfo.value)

def test_receive_signal_non_dict_and_binary():
    class FakeWS:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.TEXT, "[1]", None)
    ws = FakeWS()
    assert asyncio.run(m.receive_signal(ws, timeout=1)) is None

    class FakeWS2:
        async def receive(self, timeout=None):
            return aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, b"x", None)
    ws2 = FakeWS2()
    assert asyncio.run(m.receive_signal(ws2, timeout=1)) is None

def test_relay_stops_on_close():
    class FakeWS:
        def __init__(self):
            self.sent_str = []
            self.responses = [
                asyncio.TimeoutError(),
                aiohttp.WSMessage(aiohttp.WSMsgType.CLOSED, None, None)
            ]

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

def test_main_prints_name_for_empty_timeout(monkeypatch, capsys):
    async def fake_update(args):
        raise asyncio.TimeoutError()
    monkeypatch.setattr(m, "update_device", fake_update)
    monkeypatch.setattr(sys, "argv", ["arkkvm_update_cert", "http://dev", "--mode", "disabled", "--no-password"])
    ret = m.main()
    out, err = capsys.readouterr()
    assert ret == 1
    assert "Error: TimeoutError" in err
