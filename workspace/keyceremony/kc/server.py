"""HTTP surface: ceremony console API + watchstander desk.

Run:  python -m kc.server --root ./data --port 8080

Security layering
-----------------
Every request (other than health, the console page and the login handshake)
must present ``Authorization: Bearer <token>`` from a terminal-attested
login. Sessions bind person + duty snapshot + device + attestation deadline.

* Queries are admitted by duty scope.
* Ordinary ceremony steps require CEREMONY_EXEC and must be driven from the
  session's own bound terminal.
* The four guarded lifecycle operations — policy/rule revision
  (POLICY_REVISE), terminating an active flow (FLOW_ABORT), publishing a new
  generation (PUBLISH) and purging retired material (OP_PURGE) — are NOT
  callable directly. They create an authorization order first, which a
  second person on a different terminal with the complementary duty then
  approves.

The orchestrator library itself remains directly importable and callable
without all this (scripts/tests use it); this gate exists only at the HTTP
boundary.
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import crypto
from .ceremony import Orchestrator
from .desk import (
    ACTION_CATALOGUE, AUDIT_READ, CEREMONY_EXEC, KEYS_READ, RULES_GOVERNOR,
    WatchDesk,
)
from .errors import CeremonyError, Forbidden, SessionError
from .fleet import Fleet
from .storage import Store
from . import export as export_mod
from . import bootstrap as bootstrap_mod

CONSOLE_HTML = os.path.join(os.path.dirname(__file__), "console.html")

# route -> required read scope (GET)
SCOPE = {
    "/api/policies": "policies",
    "/api/participants": "participants",
    "/api/ceremonies": "ceremonies",
    "/api/keys": "keys",
    "/api/audit": "audit",
    "/api/export": "audit",
    "/api/sessions": "audit",
    "/api/orders": None,           # any authenticated session
    "/api/me": None,
}

GUARDED = {
    "publish": "PUBLISH",
    "abort": "FLOW_ABORT",
}


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

    def _bearer(self) -> str | None:
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[7:].strip()
        return None

    def _with_desk(self, fn, scope: str | None = None,
                   duty: str | None = None):
        """Run fn(desk, orch, body, session) under the store lock.

        State is loaded inside the lock, expired orders are swept, and the
        session is validated before fn runs. State is also saved when fn
        raises a CeremonyError: a fail-closed order decision (CLOSED + audit
        entry) must be durable even though the request returns an error.
        Orchestrator mutations raise before touching state when they reject,
        so this never persists a half-finished target change.
        """
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "BAD_JSON"})
        try:
            with self.app.store.locked():
                orch = Orchestrator(self.app.store)
                desk = WatchDesk(orch)
                desk.sweep_expired()
                session = desk.authenticate(self._bearer(), scope=scope,
                                            duty=duty)
                try:
                    result = fn(desk, orch, body, session)
                except CeremonyError:
                    orch.save()  # persist fail-closed order decisions
                    raise
                orch.save()
            self._send(200, result)
        except CeremonyError as e:
            self._error(e)
        except KeyError as e:
            self._send(400, {"error": "MISSING_FIELD", "field": str(e)})
        except Exception as e:  # noqa: BLE001 - surface unexpected failures
            self._send(500, {"error": "INTERNAL", "message": str(e)})

    def _with_orch_public(self, fn):
        """Unauthenticated lock context (login handshake only)."""
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "BAD_JSON"})
        try:
            with self.app.store.locked():
                orch = Orchestrator(self.app.store)
                desk = WatchDesk(orch)
                result = fn(desk, orch, body)
                orch.save()
            self._send(200, result)
        except CeremonyError as e:
            self._error(e)
        except KeyError as e:
            self._send(400, {"error": "MISSING_FIELD", "field": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": "INTERNAL", "message": str(e)})

    # ---- routing: GET ----------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        if path in ("/", "/index.html"):
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

        def run(desk, orch, body, session):
            if path == "/api/me":
                return {"session": desk.public_session(session),
                        "actions": desk.action_view(session)}
            if path == "/api/policies":
                return {"policies": list(orch.state["policies"].values())}
            if path == "/api/participants":
                return {"participants": orch.state["participants"],
                        "devices": orch.state["devices"],
                        "duty_grants": orch.state["duty_grants"]}
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
            if path == "/api/orders":
                return {"orders": desk.list_orders(),
                        "catalogue": ACTION_CATALOGUE}
            if path == "/api/sessions":
                return {"sessions": desk.list_sessions()}
            if path.startswith("/api/ceremonies/"):
                cid = path.rsplit("/", 1)[-1]
                return orch.public_ceremony(cid)
            if path.startswith("/api/orders/"):
                oid = path.rsplit("/", 1)[-1]
                o = desk.state["orders"].get(oid)
                if o is None:
                    from .errors import NotFound
                    raise NotFound(f"unknown order {oid}")
                return desk.public_order(o)
            self._send(404, {"error": "NOT_FOUND"})
            return None

        scope = None
        if path in SCOPE:
            scope = SCOPE[path]
        elif path.startswith("/api/ceremonies/"):
            scope = "ceremonies"
        elif path.startswith("/api/orders/"):
            scope = None
        self._with_desk(run, scope=scope)

    # ---- routing: POST ---------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        path = u.path

        # ---- public: login handshake -------------------------------------
        if path == "/api/login/challenge":
            def challenge(desk, orch, body):
                return desk.login_challenge(body["device_id"])
            return self._with_orch_public(challenge)

        if path == "/api/login":
            def do_login(desk, orch, body):
                return desk.login(body["device_id"], body["quote"])
            return self._with_orch_public(do_login)

        # demo helper: let the server-side wallet mint a login quote for a
        # terminal (models the HSM producing a quote; no secret leaves the
        # wallet file)
        if path == "/api/devices/prepare-login-quote":
            def prepare(desk, orch, body):
                did = body["device_id"]
                ch = desk.login_challenge(did)
                w = self.app.fleet.get(did)
                quote = w.quote(crypto.b64d(ch["challenge"]))
                return {"device_id": did, "challenge": ch["challenge"],
                        "quote": quote}
            return self._with_orch_public(prepare)

        # ---- logout -------------------------------------------------------
        if path == "/api/logout":
            return self._with_desk(
                lambda desk, orch, body, s: desk.logout(s["token_id"]))

        # ---- authorization orders ----------------------------------------
        if path == "/api/orders":
            def create(desk, orch, body, session):
                return desk.create_order(session, body["op"],
                                         body.get("payload", {}))
            return self._with_desk(create)

        if path.endswith("/approve") or path.endswith("/reject") \
                or path.endswith("/withdraw"):
            oid = path.split("/")[3]
            decision = path.rsplit("/", 1)[-1]

            def decide(desk, orch, body, session):
                if decision == "approve":
                    return desk.approve_order(session, oid,
                                              body.get("digest"))
                if decision == "reject":
                    return desk.reject_order(session, oid,
                                             body.get("reason", ""))
                return desk.withdraw_order(session, oid,
                                           body.get("reason", ""))
            return self._with_desk(decide)

        # ---- device / duty administration --------------------------------
        if path == "/api/devices/revoke":
            def revoke(desk, orch, body, session):
                return desk.revoke_device(session, body["device_id"],
                                          body.get("reason", ""))
            return self._with_desk(revoke, duty=RULES_GOVERNOR)

        if path == "/api/duty-grants":
            def grants(desk, orch, body, session):
                return desk.set_grants(session["token_id"],
                                       body["participant_id"], body["duties"])
            return self._with_desk(grants, duty=RULES_GOVERNOR)

        # ---- enrollment ---------------------------------------------------
        if path == "/api/participants":
            def enroll(desk, orch, body, session):
                rec = orch.enroll_participant(
                    body["participant_id"], body["name"], body["role"])
                if body.get("provision_device", True):
                    did = body.get("device_id",
                                   "dev_" + body["participant_id"])
                    if not self.app.fleet.has(did):
                        self.app.fleet.provision(did, body["name"])
                    w = self.app.fleet.get(did)
                    orch.bind_device(body["participant_id"], w,
                                     label=body["role"])
                    rec["device_id"] = did
                return rec
            return self._with_desk(enroll, duty=RULES_GOVERNOR)

        # direct policy creation/revision is a guarded four-eyes action
        if path == "/api/policies":
            return self._send(403, {
                "error": "GUARDED_ACTION",
                "message": "rule changes require an authorization order "
                           "(POST /api/orders op=POLICY_REVISE)"})

        # ---- ceremonies ---------------------------------------------------
        if path == "/api/ceremonies/open":
            def open_c(desk, orch, body, session):
                return orch.open_ceremony(
                    body["kind"], body["policy_id"], body["purpose"],
                    session["participant_id"],
                    lost_participants=body.get("lost_participants"),
                    replacement_specs=body.get("replacement_specs"),
                    target_version=body.get("target_version"))
            return self._with_desk(open_c, duty=CEREMONY_EXEC)

        if path.startswith("/api/ceremonies/"):
            parts = path.strip("/").split("/")
            cid = parts[2]
            action = parts[3] if len(parts) > 3 else ""

            if action in GUARDED:
                return self._send(403, {
                    "error": "GUARDED_ACTION",
                    "op": GUARDED[action],
                    "message": f"{GUARDED[action]} requires a four-eyes "
                               "authorization order (POST /api/orders)"})

            def step(desk, orch, body, session):
                if action in ("attest", "receive", "confirm",
                              "submit-share"):
                    did = body["device_id"]
                    if did != session["device_id"]:
                        raise Forbidden(
                            "device actions must be driven from the terminal "
                            f"bound to the session ({session['device_id']}), "
                            f"not {did}")
                if action == "attest":
                    return self.app.fleet.attest(
                        orch, cid, body["device_id"],
                        bad_measurement=body.get("bad_measurement", False))
                if action == "receive":
                    return self.app.fleet.receive(orch, cid,
                                                  body["device_id"])
                if action == "confirm":
                    return self.app.fleet.confirm(
                        orch, cid, body["device_id"],
                        note=body.get("note", ""))
                if action == "submit-share":
                    return self.app.fleet.submit_recovery(
                        orch, cid, body["device_id"],
                        source_ceremony_id=body.get("source_ceremony_id"))
                if action == "commit":
                    c = orch.state["ceremonies"].get(cid)
                    if c is not None and c["kind"] == "DESTROY":
                        raise Forbidden(
                            "purging retired material (DESTROY commit) "
                            "requires a four-eyes authorization order "
                            "(op=OP_PURGE)")
                    return orch.commit(cid, session["participant_id"],
                                       expected_active=body.get(
                                           "expected_active"))
                self._send(404, {"error": "NOT_FOUND"})
                return None

            return self._with_desk(step, duty=CEREMONY_EXEC)

        # ---- signing test interface --------------------------------------
        if path == "/api/sign":
            def sign(desk, orch, body, session):
                return orch.sign(body["purpose"], body["message"].encode())
            return self._with_desk(sign, duty=CEREMONY_EXEC)

        if path == "/api/verify":
            def verify(desk, orch, body, session):
                return orch.verify(body["purpose"],
                                   body["message"].encode(), body["sig"])
            return self._with_desk(verify, scope="keys")

        self._send(404, {"error": "NOT_FOUND"})


def serve(root: str, port: int = 8080, host: str = "127.0.0.1",
          auto_bootstrap: bool = True):
    app = App(root)
    if auto_bootstrap:
        bootstrap_mod.bootstrap(root)
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
    ap.add_argument("--no-bootstrap", action="store_true",
                    help="do not auto-bootstrap participants/duties")
    a = ap.parse_args(argv)
    serve(a.root, a.port, a.host, auto_bootstrap=not a.no_bootstrap)


if __name__ == "__main__":
    main()
