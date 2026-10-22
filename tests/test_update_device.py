import argparse
import asyncio
import base64
import json
import ssl

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
            if url.endswith("/webrtc/session"):
                return FakeResponse({"sd": self.answer_sd})
            return FakeResponse({})

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

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
            self.channel.handlers["open"]()

        async def close(self):
            self.closed = True
            self.device.closed = True

    monkeypatch.setattr(m, "RTCPeerConnection", lambda: FakePC(dev))
    monkeypatch.setattr(
        m.aiohttp,
        "TCPConnector",
        lambda ssl=None: setattr(dev, "connector_ssl", ssl) or None,
    )
    def fake_client_session(**kwargs):
        dev.session = FakeSession(dev.answer_sd)
        return dev.session

    monkeypatch.setattr(
        m.aiohttp,
        "ClientSession",
        fake_client_session,
    )
    async def dummy_wait(pc, timeout):
        return None

    monkeypatch.setattr(m, "wait_for_ice_gathering", dummy_wait)
    return dev


def test_disabled_mode_no_password_no_reboot(device, capsys):
    args = make_args()
    asyncio.run(m.update_device(args))
    # Only webrtc post
    assert len(device.session.posts) == 1
    url, json_body, headers = device.session.posts[0]
    assert url.endswith("/webrtc/session")
    assert headers == {}
    # Posted sd decodes to offer
    offer = base64.b64decode(json_body["sd"]).decode()
    assert json.loads(offer) == {"sdp": "v=0 offer", "type": "offer"}
    # Remote description set
    assert device.remote.sdp == "v=0 answer"
    # Sent RPC calls
    assert device.sent[0]["method"] == "setTLSState"
    assert device.sent[0]["params"]["state"] == {"mode": "disabled"}
    assert device.sent[1]["method"] == "getTLSState"
    # Device closed
    assert device.closed
    out, err = capsys.readouterr()
    assert "TLS mode successfully updated to 'disabled'." in out
    assert "Reboot the ArkKVM to activate the new TLS configuration." in out


def test_password_login(device, capsys):
    args = make_args(password="pw")
    asyncio.run(m.update_device(args))
    # Two posts: login and webrtc
    assert len(device.session.posts) == 2
    login_url, _, _ = device.session.posts[0]
    webrtc_url, _, webrtc_headers = device.session.posts[1]
    assert login_url.endswith("/auth/login-local")
    assert webrtc_url.endswith("/webrtc/session")
    assert webrtc_headers == {"X-CSRF-Token": "tok"}


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


def test_invalid_answer(device, capsys):
    device.answer_sd = "!!!"
    args = make_args()
    with pytest.raises(m.ArkKVMError, match="invalid WebRTC answer"):
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
