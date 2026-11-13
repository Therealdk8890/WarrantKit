"""Loopback-only authenticated checkpoint API reference.

This reference intentionally refuses non-loopback binds. It is NOT a
production remote authority: TLS, independent identity, authorization,
secret rotation and rollback-resistant storage remain external obligations.
"""
from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address

from .agentcontainment_fence_recovery import TrustedRegistryCheckpoint
from .checkpoint_sqlite_reference import SQLiteCheckpointAuthority


def make_checkpoint_server(host: str, port: int, *, database_path: str,
                           bearer_token: str) -> ThreadingHTTPServer:
    """Build an authenticated local reference endpoint, never a public bind."""
    if not ip_address(host).is_loopback:
        raise ValueError("checkpoint reference API must bind to loopback")
    if not isinstance(bearer_token, str) or len(bearer_token) < 32:
        raise ValueError("checkpoint API token must have at least 32 characters")
    authority = SQLiteCheckpointAuthority(database_path)
    expected = ("Bearer " + bearer_token).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            if hmac.compare_digest(supplied, expected):
                return True
            self._reply(401, {"error": "unauthorized"})
            return False

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if self.path != "/v1/checkpoints/advance":
                self._reply(404, {"error": "not found"})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    self._reply(413, {"error": "invalid request size"})
                    return
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict) or set(payload) != {
                    "agent_id", "epoch", "fence_sha256", "incident_sha256"
                }:
                    raise ValueError("invalid checkpoint fields")
                proposed = TrustedRegistryCheckpoint(**payload)
                changed = authority.advance(proposed)
            except (ValueError, TypeError, KeyError) as exc:
                self._reply(400, {"error": "invalid checkpoint"})
                return
            except Exception:
                self._reply(409, {"error": "checkpoint denied or unavailable"})
                return
            self._reply(200, {"advanced": changed})

        def do_GET(self) -> None:
            if not self._authorized():
                return
            prefix = "/v1/checkpoints/"
            if not self.path.startswith(prefix):
                self._reply(404, {"error": "not found"})
                return
            agent_id = self.path[len(prefix):]
            if not agent_id or "/" in agent_id or "?" in agent_id:
                self._reply(400, {"error": "invalid agent"})
                return
            try:
                record = authority.read(agent_id)
            except Exception:
                self._reply(503, {"error": "checkpoint unavailable"})
                return
            if record is None:
                self._reply(404, {"error": "checkpoint missing"})
                return
            self._reply(200, {
                "agent_id": record.agent_id, "epoch": record.epoch,
                "fence_sha256": record.fence_sha256,
                "incident_sha256": record.incident_sha256,
            })

        def log_message(self, format, *args):
            # Do not log bearer tokens or arbitrary request paths.
            pass

    return ThreadingHTTPServer((host, port), Handler)
