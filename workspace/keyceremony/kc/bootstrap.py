"""Bootstrap a demo environment: fixed roles, devices, policy, duty grants.

Usage: python -m kc.bootstrap --root ./kc-data

The four ceremony participants additionally receive watchstander *duties*.
Duties form complementary requester/approver pairs, split across people and
terminals:

  alice (ROOT_OWNER)   requester side: RULES_AUTHOR, FLOW_CONTROLLER,
                       RELEASE_MANAGER, MATERIAL_CUSTODIAN (+ CEREMONY_EXEC)
  bruno (KEY_STEWARD)  complementary approver side: RULES_GOVERNOR,
                       FLOW_SUPERVISOR, RELEASE_VERIFIER, MATERIAL_AUDITOR
  carla / diego        CEREMONY_EXEC (drive ordinary ceremony steps)
  erin                 AUDIT_READ only (read-only auditor: demonstrates the
                       duty-gated query/403 path)
"""

from __future__ import annotations

import argparse
import os

from . import policy as P
from .attestation import DeviceWallet, provision_device
from .ceremony import Orchestrator
from .desk import (
    AUDIT_READ, CEREMONY_EXEC, FLOW_CONTROLLER, FLOW_SUPERVISOR,
    KEYS_READ, MATERIAL_AUDITOR, MATERIAL_CUSTODIAN, RELEASE_MANAGER,
    RELEASE_VERIFIER, RULES_AUTHOR, RULES_GOVERNOR, WatchDesk,
)
from .storage import Store

ROSTER = [
    ("alice", "Alice — Security Officer", P.ROOT_OWNER),
    ("bruno", "Bruno — HSM Steward", P.KEY_STEWARD),
    ("carla", "Carla — Independent Witness", P.WITNESS_SHAREHOLDER),
    ("diego", "Diego — Enclave Operator", P.ENCLAVE_OPERATOR),
]

# duty grants are complementary-pair separated by construction: no person
# holds both sides of any four-eyes pair.
DUTY_GRANTS = {
    "alice": [RULES_AUTHOR, FLOW_CONTROLLER, RELEASE_MANAGER,
              MATERIAL_CUSTODIAN, CEREMONY_EXEC, KEYS_READ],
    "bruno": [RULES_GOVERNOR, FLOW_SUPERVISOR, RELEASE_VERIFIER,
              MATERIAL_AUDITOR, CEREMONY_EXEC, KEYS_READ, AUDIT_READ],
    "carla": [CEREMONY_EXEC, KEYS_READ, AUDIT_READ],
    "diego": [CEREMONY_EXEC, KEYS_READ],
}

# An additional, roster-outside read-only auditor.
AUDITOR = ("erin", "Erin — Independent Auditor", P.WITNESS_SHAREHOLDER,
           "dev_erin")


def bootstrap(root: str, threshold: int = 3, policy_id: str = "pol-root-v1",
              purposes=("root-signing",)):
    store = Store(root)
    wallet_dir = f"{root}/wallets"
    os.makedirs(wallet_dir, exist_ok=True)
    with store.locked():
        orch = Orchestrator(store)
        desk = WatchDesk(orch)
        slots = []
        for pid, name, role in ROSTER:
            try:
                orch.enroll_participant(pid, name, role)
            except Exception:
                pass
            did = "dev_" + pid
            wallet_path = f"{wallet_dir}/{did}.wallet.json"
            if os.path.exists(wallet_path):
                w = DeviceWallet.load(wallet_path)
            else:
                w = provision_device(did, name)
                w.save(wallet_path)
            if did not in orch.state["devices"]:
                orch.bind_device(pid, w, label=role)
            slots.append((pid, role, did))
        # read-only auditor terminal (not on the ceremony policy roster)
        apid, aname, arole, adid = AUDITOR
        if apid not in orch.state["participants"]:
            orch.enroll_participant(apid, aname, arole)
        awallet_path = f"{wallet_dir}/{adid}.wallet.json"
        if not os.path.exists(awallet_path):
            provision_device(adid, aname).save(awallet_path)
        if adid not in orch.state["devices"]:
            orch.bind_device(apid, DeviceWallet.load(awallet_path), label=arole)
        # initial duty grants (trusted bootstrap; later changes go through the
        # duty-admin API and require RULES_GOVERNOR)
        for pid, duties in DUTY_GRANTS.items():
            if pid not in orch.state["duty_grants"]:
                desk.set_grants(None, pid, duties)
        if apid not in orch.state["duty_grants"]:
            desk.set_grants(None, apid, [AUDIT_READ])
        if policy_id not in orch.state["policies"]:
            orch.create_policy(policy_id, "Bootstrapped root key policy",
                               threshold, slots, purposes=purposes)
        orch.save()
    return {
        "root": root,
        "policy_id": policy_id,
        "threshold": threshold,
        "participants": [{"participant_id": pid, "device_id": "dev_" + pid,
                          "role": role, "duties": DUTY_GRANTS.get(pid, [])}
                         for pid, _, role in ROSTER] +
                        [{"participant_id": apid, "device_id": adid,
                          "role": arole, "duties": [AUDIT_READ]}],
        "purposes": list(purposes),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--threshold", type=int, default=3)
    a = ap.parse_args(argv)
    info = bootstrap(a.root, a.threshold)
    print("bootstrapped:")
    for p in info["participants"]:
        print(f"  {p['participant_id']:<8} {p['role']:<24} {p['device_id']}")
        for d in p["duties"]:
            print(f"      duty: {d}")
    print(f"policy {info['policy_id']} threshold={info['threshold']}")


if __name__ == "__main__":
    main()
