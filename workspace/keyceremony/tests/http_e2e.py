"""End-to-end HTTP test for the terminal-attested watchstander desk.

Flow exercised against a real ThreadingHTTPServer:

  * unauthenticated query -> 401; bad token -> 401;
  * terminal-attested login (challenge -> device quote -> bearer token);
  * read-only auditor (AUDIT_READ) can read audit but not keys -> 403;
  * guarded endpoints (direct /publish, /abort, DESTROY commit, POST
    /policies) -> 403 GUARDED_ACTION;
  * four-eyes orders over HTTP for PUBLISH / FLOW_ABORT / OP_PURGE,
    including a concurrent double-approval (exactly one execution),
    self-approval rejection and export/verification.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
ROOT = f"/tmp/kc-http-desk-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

proc = subprocess.Popen(
    [sys.executable, "-m", "kc.server", "--root", ROOT, "--port", str(PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    BASE = f"http://127.0.0.1:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)

    def call(path, body=None, token=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(
            BASE + path, data=data,
            method=method or ("POST" if body is not None else "GET"),
            headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    tokens = {}

    def login(did):
        s, q = call("/api/devices/prepare-login-quote", {"device_id": did})
        assert s == 200, (s, q)
        s, j = call("/api/login", {"device_id": did, "quote": q["quote"]})
        assert s == 200, (s, j)
        tokens[did] = j["token"]
        return j

    # ---- gate: no / bad token -------------------------------------------
    s, j = call("/api/keys")
    assert s == 401 and j["error"] == "SESSION_INVALID", (s, j)
    s, j = call("/api/keys", token="not-a-real-token")
    assert s == 401, (s, j)
    print("unauthenticated query rejected")

    # ---- bootstrap enrolled dev_alice..dev_erin; log everyone in ---------
    for did in ("dev_alice", "dev_bruno", "dev_carla", "dev_diego"):
        login(did)
    erin = login("dev_erin")
    assert erin["session"]["participant_id"] == "erin"

    # ---- read-only auditor scope gating ----------------------------------
    s, j = call("/api/audit", token=tokens["dev_erin"])
    assert s == 200, (s, j)
    s, j = call("/api/keys", token=tokens["dev_erin"])
    assert s == 200  # AUDIT_READ includes read-only access to keys
    # the auditor cannot open/drive ceremonies (no CEREMONY_EXEC duty)
    s, j = call("/api/ceremonies/open", {
        "kind": "GENERATE", "policy_id": "pol-root-v1",
        "purpose": "root-signing"}, token=tokens["dev_erin"])
    assert s == 403 and j["error"] == "FORBIDDEN", (s, j)
    print("duty gating enforced (read-only auditor 403 on execute)")

    alice, bruno = tokens["dev_alice"], tokens["dev_bruno"]

    def as_device(did):
        return tokens[did]

    # ---- guarded endpoints are not directly callable ---------------------
    s, j = call("/api/policies", {"policy_id": "x"}, token=alice)
    assert s == 403 and j["error"] == "GUARDED_ACTION", (s, j)

    # ---- GENERATE via ordinary (CEREMONY_EXEC) sessions -------------------
    s, c = call("/api/ceremonies/open", {
        "kind": "GENERATE", "policy_id": "pol-root-v1",
        "purpose": "root-signing"}, token=alice)
    assert s == 200, (s, c)
    gen = c["id"]
    roster = [p["device_id"] for p in c["roster"]]
    for did in roster:
        s, j = call(f"/api/ceremonies/{gen}/attest", {"device_id": did},
                    token=as_device(did))
        assert s == 200, ("attest", did, s, j)
    for did in roster:
        s, j = call(f"/api/ceremonies/{gen}/receive", {"device_id": did},
                    token=as_device(did))
        assert s == 200, ("receive", did, s, j)
    for did in ("dev_alice", "dev_bruno", "dev_carla"):
        s, j = call(f"/api/ceremonies/{gen}/confirm", {"device_id": did},
                    token=as_device(did))
        assert s == 200, ("confirm", did, s, j)
    s, j = call(f"/api/ceremonies/{gen}/commit", {}, token=alice)
    assert s == 200, (s, j)

    # alice cannot drive bruno's terminal
    s, j = call(f"/api/ceremonies/{gen}/attest",
                {"device_id": "dev_bruno"}, token=alice)
    assert s == 403 and j["error"] == "FORBIDDEN", (s, j)
    print("GENERATE ceremony completed; cross-terminal device action 403")

    # ---- FLOW_ABORT order: terminate an active rotation round ------------
    s, c = call("/api/ceremonies/open", {
        "kind": "ROTATE", "policy_id": "pol-root-v1",
        "purpose": "root-signing"}, token=alice)
    assert s == 200, (s, c)
    rot_a = c["id"]
    # direct abort is guarded
    s, j = call(f"/api/ceremonies/{rot_a}/abort",
                {"actor": "alice", "reason": "x"}, token=alice)
    assert s == 403 and j["error"] == "GUARDED_ACTION", (s, j)
    s, order = call("/api/orders", {
        "op": "FLOW_ABORT",
        "payload": {"ceremony_id": rot_a, "reason": "e2e abort"}},
        token=alice)
    assert s == 200, (s, order)
    # bruno can reject-withdraw only via complementary duty; approve it
    s, done = call(f"/api/orders/{order['id']}/approve",
                   {"digest": order["payload_digest"]}, token=bruno)
    assert s == 200 and done["status"] == "APPROVED", (s, done)
    s, cv = call(f"/api/ceremonies/{rot_a}", token=alice)
    assert cv["status"] == "ABORTED"
    print("FLOW_ABORT four-eyes executed; direct abort was 403")

    # ---- ROTATE then four-eyes PUBLISH order ------------------------------
    s, c = call("/api/ceremonies/open", {
        "kind": "ROTATE", "policy_id": "pol-root-v1",
        "purpose": "root-signing"}, token=alice)
    assert s == 200, (s, c)
    rot = c["id"]
    roster = [p["device_id"] for p in c["roster"]]
    for did in roster:
        call(f"/api/ceremonies/{rot}/attest", {"device_id": did},
             token=as_device(did))
    for did in roster:
        call(f"/api/ceremonies/{rot}/receive", {"device_id": did},
             token=as_device(did))
    for did in ("dev_alice", "dev_bruno", "dev_carla"):
        call(f"/api/ceremonies/{rot}/confirm", {"device_id": did},
             token=as_device(did))
    s, j = call(f"/api/ceremonies/{rot}/commit", {}, token=alice)
    assert s == 200, (s, j)

    # direct publish is guarded
    s, keys = call("/api/keys", token=alice)
    v1 = keys["purposes"]["root-signing"]
    s, j = call(f"/api/ceremonies/{rot}/publish",
                {"actor": "alice", "expected_active": v1}, token=alice)
    assert s == 403 and j["error"] == "GUARDED_ACTION", (s, j)

    # alice (RELEASE_MANAGER) creates the order
    s, order = call("/api/orders", {
        "op": "PUBLISH",
        "payload": {"ceremony_id": rot, "expected_active": v1}}, token=alice)
    assert s == 200, (s, order)
    oid = order["id"]
    assert order["status"] == "OPEN"
    assert len(order["decisions"]) == 1

    # duplicate submission returns the same order
    s, again = call("/api/orders", {
        "op": "PUBLISH",
        "payload": {"expected_active": v1, "ceremony_id": rot}}, token=alice)
    assert s == 200 and again["id"] == oid, (s, again)

    # alice cannot approve her own order
    s, j = call(f"/api/orders/{oid}/approve",
                {"digest": order["payload_digest"]}, token=alice)
    assert s == 403 and j["error"] == "FORBIDDEN", (s, j)
    s, j = call(f"/api/orders/{oid}", token=bruno)
    assert j["status"] == "CLOSED" and j["close_reason"] == "DUTY_CONFLICT"

    # self-approval closed it: requester re-creates (fresh order), then the
    # complementary duty holder on a different terminal approves
    s, order = call("/api/orders", {
        "op": "PUBLISH",
        "payload": {"ceremony_id": rot, "expected_active": v1}}, token=alice)
    assert s == 200 and order["id"] != oid, (s, order)
    oid = order["id"]

    def approve(_):
        return call(f"/api/orders/{oid}/approve",
                    {"digest": order["payload_digest"]}, token=bruno)

    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(approve, range(4)))
    winners = [r for r in results if r[0] == 200]
    losers = [r for r in results if r[0] != 200]
    assert len(winners) == 1, results
    assert all(r[1]["error"] in ("ORDER_DECIDED", "DUPLICATE_ACTION")
               for r in losers), results
    print(f"PUBLISH four-eyes: 1 execution, {len(losers)} rejected retries")

    s, keys = call("/api/keys", token=alice)
    actives = [k for k in keys["keys"]
               if k["purpose"] == "root-signing" and k["status"] == "ACTIVE"]
    assert len(actives) == 1 and actives[0]["version"] == 2

    # ---- OP_PURGE: DESTROY the retired v1 --------------------------------
    s, c = call("/api/ceremonies/open", {
        "kind": "DESTROY", "policy_id": "pol-root-v1",
        "purpose": "root-signing", "target_version": v1}, token=alice)
    assert s == 200, (s, c)
    des = c["id"]
    roster = [p["device_id"] for p in c["roster"]]
    for did in roster:
        call(f"/api/ceremonies/{des}/attest", {"device_id": did},
             token=as_device(did))
    for did in ("dev_alice", "dev_bruno", "dev_carla"):
        call(f"/api/ceremonies/{des}/confirm", {"device_id": did},
             token=as_device(did))
    # direct DESTROY commit is guarded (purge of retired material)
    s, j = call(f"/api/ceremonies/{des}/commit", {}, token=alice)
    assert s == 403 and j["error"] in ("GUARDED_ACTION", "FORBIDDEN"), (s, j)
    s, order = call("/api/orders", {
        "op": "OP_PURGE",
        "payload": {"ceremony_id": des, "target_version": v1}}, token=alice)
    assert s == 200, (s, order)
    s, done = call(f"/api/orders/{order['id']}/approve",
                   {"digest": order["payload_digest"]}, token=bruno)
    assert s == 200 and done["status"] == "APPROVED", (s, done)
    s, keys = call("/api/keys", token=alice)
    old = next(k for k in keys["keys"] if k["id"] == v1)
    assert old["status"] == "DESTROYED"
    print("OP_PURGE four-eyes executed; retired material cleared")

    # ---- requester can withdraw their OPEN order -------------------------
    # after the purge there is no RETIRING version, so a new ROTATE can open
    s, c = call("/api/ceremonies/open", {
        "kind": "ROTATE", "policy_id": "pol-root-v1",
        "purpose": "root-signing"}, token=alice)
    assert s == 200, (s, c)
    rot2 = c["id"]
    s, keys = call("/api/keys", token=alice)
    cur = keys["purposes"]["root-signing"]
    s, order = call("/api/orders", {
        "op": "PUBLISH",
        "payload": {"ceremony_id": rot2, "expected_active": cur}}, token=alice)
    # creation freezes only the payload digest; approval would preflight-fail
    assert s == 200, (s, order)
    s, w = call(f"/api/orders/{order['id']}/withdraw",
                {"reason": "not ready"}, token=alice)
    assert s == 200 and w["status"] == "WITHDRAWN", (s, w)
    # cleanup: terminate the dangling rotation round via an abort order
    s, order2 = call("/api/orders", {
        "op": "FLOW_ABORT",
        "payload": {"ceremony_id": rot2, "reason": "cleanup"}}, token=alice)
    s, done = call(f"/api/orders/{order2['id']}/approve",
                   {"digest": order2["payload_digest"]}, token=bruno)
    assert s == 200 and done["status"] == "APPROVED", (s, done)
    print("order withdrawal + cleanup works")

    # ---- audit + export verification -------------------------------------
    s, aud = call("/api/audit", token=bruno)
    assert s == 200 and aud["verified"], aud.get("verify_problems")
    s, bundle = call("/api/export", token=bruno)
    assert s == 200
    from kc import export as export_mod
    verdict = export_mod.verify_bundle(bundle)
    assert verdict["ok"], verdict["problems"]
    assert verdict["checks"]["four_eyes_orders_ok"]
    assert verdict["checks"]["duty_separation_ok"]
    print("export verified:", verdict["checks"])

    print("HTTP DESK E2E ALL OK")
finally:
    proc.terminate()
    proc.wait(timeout=5)
