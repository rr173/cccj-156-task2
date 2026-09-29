"""End-to-end HTTP API test, including concurrent rotation publish race."""
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
ROOT = f"/tmp/kc-http-{PORT}"
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

    def call(path, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            BASE + path, data=data,
            method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                j = json.load(r)
                return (r.status, j)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    # ---- enrollment + policy ----
    for pid, name, role in [
            ("alice", "Alice Owner", "ROOT_OWNER"),
            ("bruno", "Bruno Steward", "KEY_STEWARD"),
            ("carla", "Carla Witness", "WITNESS_SHAREHOLDER"),
            ("diego", "Diego Op", "ENCLAVE_OPERATOR")]:
        s, j = call("/api/participants",
                    {"participant_id": pid, "name": name, "role": role})
        assert s == 200, (s, j)
    slots = [["alice", "ROOT_OWNER", "dev_alice"],
             ["bruno", "KEY_STEWARD", "dev_bruno"],
             ["carla", "WITNESS_SHAREHOLDER", "dev_carla"],
             ["diego", "ENCLAVE_OPERATOR", "dev_diego"]]
    s, j = call("/api/policies", {"policy_id": "p1", "label": "r",
                                  "threshold": 3, "slots": slots})
    assert s == 200, (s, j)

    def run_ceremony(kind, purpose="root-signing", confirmers=("dev_alice", "dev_bruno", "dev_carla"),
                     target=None, expected_active=None):
        body = {"kind": kind, "policy_id": "p1", "purpose": purpose,
                "actor": "alice"}
        if target:
            body["target_version"] = target
        s, c = call("/api/ceremonies/open", body)
        assert s == 200, (kind, s, c)
        cid = c["id"]
        roster = [p["device_id"] for p in c["roster"]]
        # stage ordering: the FULL roster must attest before shares are dealt
        for did in roster:
            s, j = call(f"/api/ceremonies/{cid}/attest", {"device_id": did})
            assert s == 200, ("attest", did, s, j)
        if kind != "DESTROY":
            for did in roster:
                s, j = call(f"/api/ceremonies/{cid}/receive", {"device_id": did})
                assert s == 200, ("receive", did, s, j)
        for did in confirmers:
            s, j = call(f"/api/ceremonies/{cid}/confirm", {"device_id": did})
            assert s == 200, ("confirm", did, s, j)
        s, j = call(f"/api/ceremonies/{cid}/commit", {"actor": "alice"})
        assert s == 200, ("commit", s, j)
        if kind == "ROTATE":
            s, j = call(f"/api/ceremonies/{cid}/publish",
                        {"actor": "alice", "expected_active": expected_active})
            assert s == 200, ("publish", s, j)
        return cid

    # ---- GENERATE ----
    run_ceremony("GENERATE")
    s, keys = call("/api/keys")
    v1 = [k for k in keys["keys"] if k["purpose"] == "root-signing"][0]
    assert v1["status"] == "ACTIVE"
    print("GENERATE ok, active:", v1["id"][:12], v1["fingerprint"])

    # ---- signing test interface ----
    s, sig = call("/api/sign", {"purpose": "root-signing", "message": "m1"})
    assert s == 200
    s, ver = call("/api/verify", {"purpose": "root-signing", "message": "m1",
                                  "sig": sig["sig"]})
    assert ver["valid"] and ver["active"]
    s, bad = call("/api/verify", {"purpose": "root-signing", "message": "forge",
                                  "sig": sig["sig"]})
    assert bad == {"valid": False}
    print("sign/verify ok; forgery rejected")

    # ---- ROTATE with concurrent competing publishers (CAS race) ----------
    s, c = call("/api/ceremonies/open",
                {"kind": "ROTATE", "policy_id": "p1", "purpose": "root-signing",
                 "actor": "alice"})
    cid = c["id"]
    roster = [p["device_id"] for p in c["roster"]]
    for did in roster:
        s, j = call(f"/api/ceremonies/{cid}/attest", {"device_id": did})
        assert s == 200, ("attest", s, j)
    for did in roster:
        s, j = call(f"/api/ceremonies/{cid}/receive", {"device_id": did})
        assert s == 200, ("receive", s, j)
    for did in ("dev_alice", "dev_bruno", "dev_carla"):
        call(f"/api/ceremonies/{cid}/confirm", {"device_id": did})
    s, j = call(f"/api/ceremonies/{cid}/commit", {"actor": "alice"})
    assert s == 200
    old_id = v1["id"]

    def publish(_):
        return call(f"/api/ceremonies/{cid}/publish",
                    {"actor": "racer", "expected_active": old_id})

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(publish, range(8)))
    codes = sorted(r[0] for r in results)
    winners = [r for r in results if r[0] == 200]
    losers = [r for r in results if r[0] != 200]
    assert len(winners) == 1, results
    assert all(r[1].get("error") == "RACE_LOST" for r in losers), results
    print(f"publish race: 1 winner, {len(losers)} RACE_LOST")

    # exactly one ACTIVE
    s, keys = call("/api/keys")
    actives = [k for k in keys["keys"]
               if k["purpose"] == "root-signing" and k["status"] == "ACTIVE"]
    assert len(actives) == 1, actives
    v2 = actives[0]
    assert v2["version"] == 2

    # old signature still verifies as historical RETIRING
    s, ver1 = call("/api/verify", {"purpose": "root-signing", "message": "m1",
                                   "sig": sig["sig"]})
    assert ver1["valid"] and ver1["status"] == "RETIRING" and not ver1["active"]
    print("historical verify ok:", ver1["status"])

    # ---- DESTROY the retired v1 ----
    run_ceremony("DESTROY", target=v1["id"])
    s, ver1b = call("/api/verify", {"purpose": "root-signing", "message": "m1",
                                    "sig": sig["sig"]})
    assert ver1b["valid"] and ver1b["status"] == "DESTROYED"
    print("destroyed-key historical signature still verifies")

    # ---- audit + export verification ----
    s, aud = call("/api/audit")
    assert s == 200 and aud["verified"], aud.get("verify_problems")
    s, bundle = call("/api/export")
    assert s == 200
    from kc import export as export_mod
    verdict = export_mod.verify_bundle(bundle)
    assert verdict["ok"], verdict["problems"]
    print("export verified:", verdict["checks"])

    print("HTTP E2E ALL OK")
finally:
    proc.terminate()
    proc.wait(timeout=5)
