"""HTTP surface: ceremony console API + signing test interface.

Run:  python -m kc.server --root ./data --port 8080

All state mutations take the exclusive store lock, so concurrent rotation
publishes serialize and lose races cleanly (409 RACE_LOST) instead of
producing two current keys. Every error type maps to a distinct status code.
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import policy as P
from . import crypto
from .ceremony import Orchestrator
from .errors import CeremonyError
from .fleet import Fleet
from .storage import Store
from . import export as export_mod

CONSOLE_HTML = os.path.join(os.path.dirname(__file__), "console.html")


class App:
    def __init__(self, root: str):
        self.store = Store(root)
        self.fleet = Fleet(os.path.join(root, "wallets"))


class Handler(BaseHTTPRequestHandler):
    app: App = None

    def log_message(self, fmt, *args):
        pass  # quiet; audit log is the record

    # ---- plumbing --------------------------------------------------------
    def _send(self, code: int, obj):
        body = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode())

    def _error(self, e: CeremonyError):
        self._send(e.http_status, {"error": e.code, "message": str(e)})

    def _with_orch(self, fn):
        """Run fn(orch, body) under the store lock; persist at the end.

        State is loaded *inside* the lock so a request never works from a
        snapshot taken while another request was mid-commit.
        """
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "BAD_JSON"})
        try:
            with self.app.store.locked():
                orch = Orchestrator(self.app.store)
                result = fn(orch, body)
                orch.save()
            self._send(200, result)
        except CeremonyError as e:
            self._error(e)
        except KeyError as e:
            self._send(400, {"error": "MISSING_FIELD", "field": str(e)})
        except Exception as e:  # noqa: BLE001 - surface unexpected failures
            self._send(500, {"error": "INTERNAL", "message": str(e)})

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        if path == "/" or path == "/index.html":
            try:
                with open(CONSOLE_HTML, "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except FileNotFoundError:
                self._send(404, {"error": "console unavailable"})
            return
        if path == "/health":
            return self._send(200, {"ok": True})

        def run(orch, _body):
            if path == "/api/policies":
                return {"policies": list(orch.state["policies"].values())}
            if path == "/api/participants":
                return {"participants": orch.state["participants"],
                        "devices": orch.state["devices"]}
            if path == "/api/ceremonies":
                return {"ceremonies": orch.list_ceremonies()}
            if path == "/api/keys":
                purpose = q.get("purpose", [None])[0]
                keys = list(orch.state["keys"].values())
                if purpose:
                    keys = [k for k in keys if k["purpose"] == purpose]
                return {"keys": sorted(keys, key=lambda k: (k["purpose"],
                                                            k["version"])),
                        "purposes": orch.state["purposes"]}
            if path == "/api/audit":
                probs = orch.audit.verify(
                    crypto.ed25519.public_from_secret(orch.seed))
                return {"entries": orch.audit.entries,
                        "verify_problems": probs,
                        "verified": not probs}
            if path == "/api/export":
                return export_mod.build_bundle(orch)
            if path.startswith("/api/ceremonies/"):
                cid = path.rsplit("/", 1)[-1]
                return orch.public_ceremony(cid)
            self._send(404, {"error": "NOT_FOUND"})
            return None

        self._with_orch(run)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path

        def run(orch, body):
            fleet = self.app.fleet
            if path == "/api/participants":
                rec = orch.enroll_participant(
                    body["participant_id"], body["name"], body["role"])
                # optional immediate device provisioning
                if body.get("provision_device", True):
                    did = body.get("device_id", "dev_" + body["participant_id"])
                    if not fleet.has(did):
                        fleet.provision(did, body["name"])
                    w = fleet.get(did)
                    orch.bind_device(body["participant_id"], w,
                                     label=body["role"])
                    rec["device_id"] = did
                return rec
            if path == "/api/policies":
                return orch.create_policy(
                    body["policy_id"], body["label"],
                    int(body["threshold"]),
                    [tuple(s) for s in body["slots"]],
                    purposes=tuple(body.get("purposes", ["root-signing"])),
                    handover_seconds=int(body.get("handover_seconds", 3600)),
                    ceremony_timeout_seconds=int(
                        body.get("ceremony_timeout_seconds", 1800)))
            if path == "/api/ceremonies/open":
                return orch.open_ceremony(
                    body["kind"], body["policy_id"], body["purpose"],
                    body["actor"],
                    lost_participants=body.get("lost_participants"),
                    replacement_specs=body.get("replacement_specs"),
                    target_version=body.get("target_version"))
            if path.endswith("/abort"):
                cid = path.split("/")[3]
                return orch.abort(cid, body["actor"], body["reason"])
            if path.endswith("/commit"):
                cid = path.split("/")[3]
                return orch.commit(cid, body["actor"],
                                   expected_active=body.get("expected_active"))
            if path.endswith("/publish"):
                cid = path.split("/")[3]
                return orch.publish_rotation(
                    cid, body["actor"], body["expected_active"])
            if path.endswith("/attest"):
                cid = path.split("/")[3]
                return fleet.attest(orch, cid, body["device_id"],
                                    bad_measurement=body.get("bad_measurement",
                                                             False))
            if path.endswith("/receive"):
                cid = path.split("/")[3]
                return fleet.receive(orch, cid, body["device_id"])
            if path.endswith("/confirm"):
                cid = path.split("/")[3]
                return fleet.confirm(orch, cid, body["device_id"],
                                     note=body.get("note", ""))
            if path.endswith("/submit-share"):
                cid = path.split("/")[3]
                return fleet.submit_recovery(
                    orch, cid, body["device_id"],
                    source_ceremony_id=body.get("source_ceremony_id"))
            if path == "/api/sign":
                return orch.sign(body["purpose"], body["message"].encode())
            if path == "/api/verify":
                return orch.verify(body["purpose"],
                                   body["message"].encode(), body["sig"])
            self._send(404, {"error": "NOT_FOUND"})
            return None

        self._with_orch(run)


def serve(root: str, port: int = 8080, host: str = "127.0.0.1"):
    app = App(root)
    Handler.app = app
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"key ceremony console: http://{host}:{port}/  (state in {root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args(argv)
    serve(a.root, a.port, a.host)


if __name__ == "__main__":
    main()
