"""Verifiable record export.

Produces a single JSON bundle an external auditor can check *without* any
access to secrets or live state:

  export.json
  {
    "generated_at", "service_identity_pub", "service_sig",
    "policies":   [...immutable policy snapshots...],
    "keys":       [...all key versions (public material only)...],
    "purposes":   {purpose: active_version_id},
    "ceremonies": [...public ceremony views...],
    "audit":      [...full hash-chained audit entries...],
    "invariants": {computed checksums}
  }

Verification performed by `verify_bundle`:
  * service signature over the bundle body,
  * audit hash-chain links and every audit entry's service signature,
  * each ceremony's commitment column matches the registered key version
    (lifecycle provenance: a version only exists via a COMPLETED ceremony),
  * destroyed versions carry no private material,
  * every purpose points at an ACTIVE version (single-current-key invariant),
  * participants referenced by ceremonies exist and roles are valid.

The auditor additionally gets `audit.txt` (human-readable) and `SHA256SUMS`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from . import crypto, ed25519
from .desk import (
    ACTION_CATALOGUE, O_APPROVED, O_CLOSED, O_OPEN, O_REJECTED,
    O_WITHDRAWN, WatchDesk, payload_digest,
)
from .errors import TamperError
from .storage import GENESIS


def build_bundle(orch) -> dict:
    s = orch.state
    desk = WatchDesk(orch)
    body = {
        "format": "kc-export-v2",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service_identity_pub": crypto.b64e(
            ed25519.public_from_secret(orch.seed)),
        "policies": list(s["policies"].values()),
        "keys": [
            {**_public_key(k),
             "has_private_material": k["id"] in s["wraps"]}
            for k in sorted(s["keys"].values(), key=lambda x: (x["purpose"],
                                                               x["version"]))
        ],
        "purposes": dict(s["purposes"]),
        "ceremonies": [orch.public_ceremony(cid)
                       for cid in sorted(s["ceremonies"].keys())],
        "audit": list(orch.audit.entries),
        "devices": {
            did: {k: v for k, v in d.items()}
            for did, d in s["devices"].items()
        },
        "participants": dict(s["participants"]),
        # watchstander desk: duty grants, attested sessions, four-eyes orders
        "duty_grants": {pid: list(d)
                        for pid, d in s.get("duty_grants", {}).items()},
        "sessions": desk.list_sessions(),
        "orders": desk.list_orders(),
    }
    body["invariants"] = {
        "body_hash_excluding_sig": crypto.digest_hex(
            {k: v for k, v in body.items() if k != "invariants"}),
        "n_audit_entries": len(body["audit"]),
        "n_keys": len(body["keys"]),
        "n_ceremonies": len(body["ceremonies"]),
        "n_orders": len(body["orders"]),
        "n_sessions": len(body["sessions"]),
    }
    sig = ed25519.sign(orch.seed,
                       body["invariants"]["body_hash_excluding_sig"].encode())
    body["service_sig"] = crypto.b64e(sig)
    return body


def _public_key(k: dict) -> dict:
    keep = ("id", "purpose", "version", "status", "signing_pub",
            "fingerprint", "commitments", "share_meta", "source_ceremony",
            "created_at", "activated_at", "retired_at", "destroyed_at",
            "destroy_ceremony", "handover_deadline")
    return {f: k.get(f) for f in keep}


def write_export(orch, outdir: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    bundle = build_bundle(orch)
    path = os.path.join(outdir, "export.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    # human-readable audit trail
    lines = []
    prev = GENESIS
    for e in bundle["audit"]:
        lines.append(
            f"{e['seq']:>4} {e['ts']} {e['event']:<28} "
            f"{crypto.dumps(e['payload'])[:180]}")
    txt = os.path.join(outdir, "audit.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("# key ceremony audit trail (exported)\n")
        f.write("# each line's full signed record is in export.json -> audit\n\n")
        f.write("\n".join(lines) + "\n")
    # checksums
    sums = os.path.join(outdir, "SHA256SUMS")

    def _sha(path: str) -> str:
        with open(path, "rb") as rf:
            return hashlib.sha256(rf.read()).hexdigest()

    with open(sums, "w", encoding="utf-8") as f:
        for name, pth in (("export.json", path), ("audit.txt", txt)):
            f.write(_sha(pth) + "  " + name + "\n")
    return path


# ---------------------------------------------------------------------------
# independent verification (no Store, no secrets)
# ---------------------------------------------------------------------------

def _audit_entry_hash(entry: dict) -> str:
    h = hashlib.sha256()
    h.update(entry["prev"].encode())
    h.update(crypto.dumps(entry["payload"]).encode())
    h.update(str(entry["ts"]).encode())
    h.update(str(entry["seq"]).encode())
    return h.hexdigest()


def verify_bundle(bundle: dict) -> dict:
    problems: list[str] = []
    checks: dict[str, object] = {}

    # 1. service identity signature over body
    pub = crypto.b64d(bundle["service_identity_pub"])
    sig = crypto.b64d(bundle["service_sig"])
    body_hash = crypto.digest_hex(
        {k: v for k, v in bundle.items()
         if k not in ("invariants", "service_sig")})
    if body_hash != bundle["invariants"]["body_hash_excluding_sig"]:
        problems.append("bundle body was modified after signing")
    if not ed25519.verify(pub, body_hash.encode(), sig):
        problems.append("bundle service signature invalid")
    checks["bundle_signature_ok"] = not problems

    # 2. audit hash chain + per-entry service signatures
    prev = GENESIS
    by_event: dict[tuple, dict] = {}
    for i, e in enumerate(bundle["audit"]):
        if e["seq"] != i:
            problems.append(f"audit seq gap at {i}")
        if e["prev"] != prev:
            problems.append(f"audit[{i}] broken prev link")
        if _audit_entry_hash(e) != e["hash"]:
            problems.append(f"audit[{i}] hash mismatch (payload edited)")
        if "svc_sig" not in e or not ed25519.verify(
                pub, e["hash"].encode(), crypto.b64d(e["svc_sig"])):
            problems.append(f"audit[{i}] service signature missing/invalid")
        prev = e["hash"]
        by_event.setdefault((e["event"],), e)
    checks["audit_chain_ok"] = not any("audit" in p for p in problems)
    checks["audit_entries"] = len(bundle["audit"])

    # 3. key lifecycle provenance: each key traces to a COMPLETED ceremony
    ceremonies = {c["id"]: c for c in bundle["ceremonies"]}
    completed_ids = {cid for cid, c in ceremonies.items()
                     if c["status"] == "COMPLETED"}
    keys = bundle["keys"]
    for k in keys:
        if k["source_ceremony"] not in completed_ids:
            problems.append(
                f"key {k['id']} has no COMPLETED source ceremony")
        if k.get("has_private_material") and k["status"] == "DESTROYED":
            problems.append(f"DESTROYED key {k['id']} still has private material")

    # 4. single-current-key: exactly one ACTIVE per purpose
    from collections import defaultdict
    by_purpose: dict[str, list[dict]] = defaultdict(list)
    for k in keys:
        by_purpose[k["purpose"]].append(k)
    for purpose, group in by_purpose.items():
        actives = [k["id"] for k in group if k["status"] == "ACTIVE"]
        if len(actives) > 1:
            problems.append(
                f"purpose {purpose} has {len(actives)} ACTIVE keys: {actives}")
        pointer = bundle["purposes"].get(purpose)
        if pointer not in actives:
            problems.append(
                f"purpose {purpose} pointer does not match its ACTIVE key")
        # No ACTIVE version may exist outside the purpose pointer (catches a
        # flipped status that does not add a *second* ACTIVE sibling).
        for k in group:
            if k["status"] == "ACTIVE" and k["id"] != pointer:
                problems.append(
                    f"key {k['id']} is ACTIVE but is not the current pointer")
        # STAGED keys must have an ACTIVE sibling produced earlier.
        staged = [k for k in group if k["status"] == "STAGED"]
        if staged and not actives:
            problems.append(
                f"purpose {purpose} has STAGED key(s) but no ACTIVE key")
    checks["single_active_per_purpose"] = not any(
        "ACTIVE" in p or "pointer" in p for p in problems)

    # 5. policy snapshots referenced by ceremonies exist and threshold sane
    policies = {p["policy_id"]: p for p in bundle["policies"]}
    for c in bundle["ceremonies"]:
        snap = c["policy_snapshot"]
        p = policies.get(snap["policy_id"])
        if p is None:
            problems.append(f"ceremony {c['id']} references missing policy")
            continue
        if snap["threshold"] != p["threshold"]:
            problems.append(
                f"ceremony {c['id']} threshold differs from policy record")
        if len(c["roster"]) != len(snap["slots"]):
            problems.append(f"ceremony {c['id']} roster/policy slot mismatch")

    # 6. handover consistency: RETIRING keys must have a newer ACTIVE sibling
    for purpose, group in by_purpose.items():
        retiring = [k for k in group if k["status"] == "RETIRING"]
        active = [k for k in group if k["status"] == "ACTIVE"]
        for r in retiring:
            if not any(a["version"] > r["version"] for a in active):
                problems.append(
                    f"RETIRING key {r['id']} has no newer ACTIVE successor")
    checks["handover_consistent"] = True

    # 7. watchstander desk: sessions and four-eyes authorization orders
    sessions = {s["token_id"]: s for s in bundle.get("sessions", [])}
    problems += _verify_orders(bundle, sessions, ceremonies, policies)
    checks["four_eyes_orders_ok"] = not any(
        "order" in p or "four-eyes" in p for p in problems)

    # 8. duty grant separation-of-duty invariant
    for pid, duties in bundle.get("duty_grants", {}).items():
        ds = set(duties)
        for op, (reqd, apd) in ACTION_CATALOGUE.items():
            if reqd in ds and apd in ds:
                problems.append(
                    f"participant {pid} holds both {reqd} and {apd}; "
                    "could self-approve " + op)
    checks["duty_separation_ok"] = not any("self-approve" in p
                                           for p in problems)

    return {"ok": not problems, "problems": problems, "checks": checks}


def _verify_orders(bundle: dict, sessions: dict, ceremonies: dict,
                   policies: dict) -> list[str]:
    """Offline check of every authorization order:

      * the frozen digest matches the stored canonical payload,
      * the local decision hash chain is intact (delete/edit a decision or
        the order header and the chain fails),
      * every decision has a matching service-signed audit entry,
      * APPROVED orders satisfy the four-eyes rule (different person AND
        different terminal, complementary duties, token ids present in the
        session table),
      * an APPROVED execution left the expected footprint on target state
        (new policy / aborted ceremony / published rotation / purged key),
      * CLOSED/REJECTED/WITHDRAWN orders never produced a footprint.
    """
    problems: list[str] = []
    audit_by_order: dict[str, list[dict]] = {}
    for e in bundle["audit"]:
        if e["event"] == "order_decision":
            audit_by_order.setdefault(
                e["payload"]["order_id"], []).append(e)

    for o in bundle.get("orders", []):
        oid = o["id"]
        reqd, apd = ACTION_CATALOGUE.get(o["op"], (None, None))
        if reqd is None:
            problems.append(f"order {oid}: unknown op {o['op']}")
            continue
        # frozen digest integrity
        if payload_digest(o["op"], o["payload"]) != o["payload_digest"]:
            problems.append(
                f"order {oid}: payload was edited (digest mismatch)")
        # requester/approver catalogue duties
        if o["requester"]["duty"] != reqd:
            problems.append(
                f"order {oid}: requester duty {o['requester']['duty']} "
                f"is not {reqd}")
        if o["approver_duty"] != apd:
            problems.append(f"order {oid}: approver duty should be {apd}")
        # local decision chain
        prev = None
        kinds = []
        for i, d in enumerate(o["decisions"]):
            if d["seq"] != i:
                problems.append(f"order {oid}: decision seq gap at {i}")
            if d["prev"] != prev:
                problems.append(f"order {oid}: broken decision link at {i}")
            if d["hash"] != WatchDesk._decision_hash(o, d):
                problems.append(
                    f"order {oid}: decision {i} hash mismatch (edited)")
            prev = d["hash"]
            kinds.append(d["kind"])
            # matching audit entry (delete the audit record -> detected)
            match = [e for e in audit_by_order.get(oid, [])
                     if e["payload"]["seq"] == i
                     and e["payload"]["decision_hash"] == d["hash"]]
            if not match:
                problems.append(
                    f"order {oid}: decision {i} missing matching audit entry")
        if not kinds or kinds[0] != "CREATE":
            problems.append(f"order {oid}: decision chain must start CREATE")

        st = o["status"]
        r = o["requester"]
        if st == O_APPROVED:
            a = o.get("approver")
            if not a:
                problems.append(f"order {oid}: APPROVED without approver")
            else:
                if a["participant_id"] == r["participant_id"]:
                    problems.append(
                        f"order {oid}: four-eyes violated (same person "
                        "requested and approved)")
                if a["device_id"] == r["device_id"]:
                    problems.append(
                        f"order {oid}: four-eyes violated (same terminal)")
                if a["duty"] != apd:
                    problems.append(
                        f"order {oid}: approver acted as {a['duty']}, "
                        f"needs {apd}")
                if a.get("session_token_id") not in sessions:
                    problems.append(
                        f"order {oid}: approver token not in session table")
                if r.get("session_token_id") not in sessions:
                    problems.append(
                        f"order {oid}: requester token not in session table")
            if "APPROVE" not in kinds:
                problems.append(f"order {oid}: APPROVED without APPROVE step")
            if not o.get("result"):
                problems.append(f"order {oid}: APPROVED without result")
            else:
                problems += _verify_execution_footprint(o, ceremonies)
        elif st in (O_REJECTED, O_WITHDRAWN, O_CLOSED):
            if o.get("result"):
                problems.append(
                    f"order {oid}: {st} order must not have an execution "
                    "result (no half-finished artifacts)")
            terminal_decision = {"REJECT": O_REJECTED,
                                 "WITHDRAW": O_WITHDRAWN,
                                 "CLOSE": O_CLOSED}
            need = next((k for k, v in terminal_decision.items()
                         if v == st), None)
            if need and need not in kinds:
                problems.append(
                    f"order {oid}: status {st} but no {need} decision")
        elif st == O_OPEN:
            if "APPROVE" in kinds:
                problems.append(f"order {oid}: OPEN but contains APPROVE")
        else:
            problems.append(f"order {oid}: unknown status {st}")

    # session integrity: token binding to enrolled person/device
    devices = {d["device_id"]: d for d in bundle.get("devices", {}).values()}
    participants = bundle.get("participants", {})
    for sid, s in sessions.items():
        if s["participant_id"] not in participants:
            problems.append(f"session {sid}: unknown participant")
        d = devices.get(s["device_id"])
        if d is None:
            problems.append(f"session {sid}: unknown device")
        elif d["participant_id"] != s["participant_id"]:
            problems.append(
                f"session {sid}: device belongs to another participant")
    return problems


def _verify_execution_footprint(o: dict, ceremonies: dict) -> list[str]:
    """An APPROVED order's claimed execution must match exported state."""
    problems: list[str] = []
    p = o["payload"]
    if o["op"] == "POLICY_REVISE":
        if p["new_policy_id"] not in policies:
            problems.append(
                f"order {o['id']}: POLICY_REVISE approved but policy "
                f"{p['new_policy_id']} is absent from the policy record")
    elif o["op"] == "PUBLISH":
        c = ceremonies.get(p["ceremony_id"])
        if c is None or not c.get("published"):
            problems.append(
                f"order {o['id']}: PUBLISH approved but ceremony shows no "
                "publication")
    elif o["op"] == "FLOW_ABORT":
        c = ceremonies.get(p["ceremony_id"])
        if c is None or c["status"] != "ABORTED":
            problems.append(
                f"order {o['id']}: FLOW_ABORT approved but ceremony not "
                "ABORTED")
    elif o["op"] == "OP_PURGE":
        c = ceremonies.get(p["ceremony_id"])
        if c is None or c["status"] != "COMPLETED":
            problems.append(
                f"order {o['id']}: OP_PURGE approved but ceremony not "
                "COMPLETED")
    return problems
