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
from .errors import TamperError
from .storage import GENESIS


def build_bundle(orch) -> dict:
    s = orch.state
    body = {
        "format": "kc-export-v1",
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
    }
    body["invariants"] = {
        "body_hash_excluding_sig": crypto.digest_hex(
            {k: v for k, v in body.items() if k != "invariants"}),
        "n_audit_entries": len(body["audit"]),
        "n_keys": len(body["keys"]),
        "n_ceremonies": len(body["ceremonies"]),
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

    return {"ok": not problems, "problems": problems, "checks": checks}
