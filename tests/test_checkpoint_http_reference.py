"""Loopback checkpoint HTTP reference integration tests."""
import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from agentcontain.checkpoint_http_reference import make_checkpoint_server


TOKEN = "reference-only-credential-" + "x" * 40


def request(url, *, token=TOKEN, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Authorization": "Bearer " + token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=body, headers=headers,
                  method="POST" if body is not None else "GET")
    try:
        with urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def test_checkpoint_api_rejects_public_bind_and_weak_secret(tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        make_checkpoint_server("0.0.0.0", 0,
                               database_path=str(tmp_path / "cp.db"),
                               bearer_token=TOKEN)
    with pytest.raises(ValueError, match="token"):
        make_checkpoint_server("127.0.0.1", 0,
                               database_path=str(tmp_path / "cp.db"),
                               bearer_token="short")


def test_checkpoint_api_auth_cas_and_restart(tmp_path):
    path = str(tmp_path / "cp.db")
    server = make_checkpoint_server("127.0.0.1", 0,
                                    database_path=path, bearer_token=TOKEN)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/v1/checkpoints"
    initial = {
        "agent_id": "agent", "epoch": 0,
        "fence_sha256": "a" * 64, "incident_sha256": None,
    }
    try:
        assert request(base + "/agent", token="wrong")[0] == 401
        assert request(base + "/agent")[0] == 404
        assert request(base + "/advance", payload=initial) == (200, {"advanced": True})
        assert request(base + "/advance", payload=initial) == (200, {"advanced": False})
        assert request(base + "/agent") == (200, initial)
        conflict = dict(initial, fence_sha256="b" * 64)
        assert request(base + "/advance", payload=conflict)[0] == 409
        gap = dict(initial, epoch=2)
        assert request(base + "/advance", payload=gap)[0] == 409
        assert request(base + "/agent") == (200, initial)
        next_epoch = dict(initial, epoch=1, fence_sha256="b" * 64)
        assert request(base + "/advance", payload=next_epoch) == (200, {"advanced": True})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    reopened = make_checkpoint_server("127.0.0.1", 0,
                                      database_path=path, bearer_token=TOKEN)
    thread = Thread(target=reopened.serve_forever, daemon=True)
    thread.start()
    try:
        assert request(f"http://127.0.0.1:{reopened.server_port}/v1/checkpoints/agent") == (
            200, next_epoch
        )
    finally:
        reopened.shutdown()
        reopened.server_close()
        thread.join(timeout=5)
