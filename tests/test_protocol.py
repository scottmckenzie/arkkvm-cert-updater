import asyncio
import json
import pytest

import arkkvm_update_cert as m

# Fake classes -------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, text="", headers=None, reason="OK", url="http://dev/x"):
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

    def post(self, url, json=None, headers=None):
        self.calls.append((url, json, headers))
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


# Tests ---------------------------------------------------------------------

def test_checked_json_success():
    resp = FakeResponse(status=200, text='{"a": 1}')
    result = asyncio.run(m.checked_json(resp))
    assert result == {"a": 1}


def test_checked_json_401_with_json_body():
    resp = FakeResponse(status=401, text='{"error":"bad"}', reason="Unauthorized", url="http://dev/x")
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.checked_json(resp))
    msg = str(exc.value)
    assert "HTTP 401" in msg
    assert "bad" in msg


def test_checked_json_500_empty_text():
    resp = FakeResponse(status=500, text='', reason="Server Error", url="http://dev/x")
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.checked_json(resp))
    assert "Server Error" in str(exc.value)


def test_checked_json_non_json_body():
    resp = FakeResponse(status=200, text="not json")
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.checked_json(resp))
    assert "non-JSON response" in str(exc.value)


def test_login_no_password():
    resp = FakeResponse(status=200, text='{}')
    session = FakeSession(resp)
    token = asyncio.run(m.login(session, "http://dev", None))
    assert token is None
    assert session.calls == []


def test_login_header_csrf_token():
    resp = FakeResponse(status=200, text='{}', headers={"X-CSRF-Token": "hdr"}, url="http://dev/x")
    session = FakeSession(resp)
    token = asyncio.run(m.login(session, "http://dev", "pw"))
    assert token == "hdr"
    assert session.calls == [("http://dev/auth/login-local", {"password": "pw"}, {"Origin": "http://dev", "Referer": "http://dev/"})]
    assert session.calls[0][2]["Origin"] == "http://dev"


def test_login_body_csrf_token():
    resp = FakeResponse(status=200, text='{"csrfToken":"body-token"}', url="http://dev/x")
    session = FakeSession(resp)
    token = asyncio.run(m.login(session, "http://dev", "pw"))
    assert token == "body-token"


def test_login_no_csrf_token():
    resp = FakeResponse(status=200, text='{}', url="http://dev/x")
    session = FakeSession(resp)
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.login(session, "http://dev", "pw"))
    assert "no CSRF token" in str(exc.value)


def test_rpc_call_success():
    pending = {}
    reply = {"id": 7, "result": {"mode": "custom"}}
    channel = FakeChannel(pending, reply)
    result = asyncio.run(m.rpc_call(channel, pending, "getTLSState", None, 7, 1))
    assert result == {"mode": "custom"}
    assert pending == {}
    assert channel.sent[0] == {"jsonrpc": "2.0", "method": "getTLSState", "id": 7}


def test_rpc_call_with_params():
    pending = {}
    reply = {"id": 1, "result": {}}
    channel = FakeChannel(pending, reply)
    params = {"state": {"mode": "disabled"}}
    result = asyncio.run(m.rpc_call(channel, pending, "setTLSState", params, 1, 1))
    assert result == {}
    assert channel.sent[0]["params"] == params


def test_rpc_call_error_with_data():
    pending = {}
    reply = {"id": 1, "error": {"code": -1, "message": "msg", "data": "detail"}}
    channel = FakeChannel(pending, reply)
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.rpc_call(channel, pending, "setTLSState", None, 1, 1))
    assert "setTLSState failed: detail" in str(exc.value)
    assert pending == {}


def test_rpc_call_error_with_message():
    pending = {}
    reply = {"id": 1, "error": {"message": "msg"}}
    channel = FakeChannel(pending, reply)
    with pytest.raises(m.ArkKVMError) as exc:
        asyncio.run(m.rpc_call(channel, pending, "setTLSState", None, 1, 1))
    assert "failed: msg" in str(exc.value)
    assert pending == {}


def test_rpc_call_timeout():
    pending = {}
    channel = FakeChannel(pending, None)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(m.rpc_call(channel, pending, "getTLSState", None, 1, 0.01))
    assert pending == {}


def test_wait_for_ice_gathering_complete():
    pc = FakePC("complete")
    asyncio.run(m.wait_for_ice_gathering(pc, 1))


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
        pc = FakePC("gathering")
        with pytest.raises(asyncio.TimeoutError):
            await m.wait_for_ice_gathering(pc, 0.01)
    asyncio.run(inner())
