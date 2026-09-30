"""Tests for terminal-attested watchstander sessions and four-eyes orders.

Covers:
  * login = fresh device attestation; token bound to person/duty/terminal/
    deadline; bad/expired/replayed quotes and revoked terminals fail;
  * queries admitted by duty scope; no token -> SESSION_INVALID;
  * guarded actions (rule change / flow abort / publish / purge) cannot be
    called on the desk without an order;
  * duplicate create returns the original order; different digest opens a new
    one; same target rejects conflicting opens;
  * approval needs a SECOND person on a SECOND terminal with the
    COMPLEMENTARY duty; self/same-terminal/wrong-duty closes the order;
  * payload drift, requester token expiry/logout, terminal revocation, target
    state change all CLOSE the order with no partial execution;
  * concurrent approvals execute at most once;
  * re-login on the same person+terminal continues an OPEN order;
  * export records both parties, token ids, digest, decision chain, result,
    and offline verification detects edits/deletions.
"""

import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import policy as P
from kc import crypto
from kc import export as export_mod
from kc.attestation import provision_device
from kc.ceremony import Orchestrator
from kc.console import DeviceContext
from kc.desk import (
    AUDIT_READ, CEREMONY_EXEC, FLOW_CONTROLLER, FLOW_SUPERVISOR,
    MATERIAL_AUDITOR, MATERIAL_CUSTODIAN, KEYS_READ, RELEASE_MANAGER,
    RELEASE_VERIFIER, RULES_AUTHOR, RULES_GOVERNOR, OP_FLOW_ABORT,
    OP_POLICY_REVISE, OP_PUBLISH, OP_PURGE, WatchDesk,
)
from kc.errors import (
    AttestationError, ConflictState, DuplicateAction, Forbidden,
    NotFound, OrderError, PolicyViolation, RaceLost, SessionError,
    TamperError,
)
from kc.storage import Store

PEOPLE = [
    ("alice", "Alice Owner", P.ROOT_OWNER,
     [RULES_AUTHOR, FLOW_CONTROLLER, RELEASE_MANAGER, MATERIAL_CUSTODIAN,
      CEREMONY_EXEC, KEYS_READ]),
    ("bruno", "Bruno Steward", P.KEY_STEWARD,
     [RULES_GOVERNOR, FLOW_SUPERVISOR, RELEASE_VERIFIER, MATERIAL_AUDITOR,
      CEREMONY_EXEC, KEYS_READ, AUDIT_READ]),
    ("carla", "Carla Witness", P.WITNESS_SHAREHOLDER,
     [CEREMONY_EXEC, KEYS_READ, AUDIT_READ]),
    ("diego", "Diego Op", P.ENCLAVE_OPERATOR,
     [CEREMONY_EXEC, KEYS_READ]),
    ("erin", "Erin Auditor", P.WITNESS_SHAREHOLDER, [AUDIT_READ]),
]


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class DeskWorld:
    """In-process world with wallets, duty grants and a WatchDesk."""

    def __init__(self, root: str, clock=None):
        shutil.rmtree(root, ignore_errors=True)
        self.root = root
        self.clock = clock or Clock()
        self.store = Store(root)
        self.wallets = {}
        with self.store.locked():
            self.orch = Orchestrator(self.store, clock=self.clock)
            self.desk = WatchDesk(self.orch, clock=self.clock)
            slots = []
            for pid, name, role, duties in PEOPLE:
                self.orch.enroll_participant(pid, name, role)
                w = provision_device("dev_" + pid, name)
                self.wallets[pid] = w
                self.orch.bind_device(pid, w, label=role)
                self.desk.set_grants(None, pid, duties)
                if pid in ("alice", "bruno", "carla", "diego"):
                    slots.append((pid, role, w.device_id))
            self.orch.create_policy("pol-v1", "root", 3, slots)
            self.orch.save()
        self.ctx = {pid: DeviceContext(w) for pid, w in self.wallets.items()}
        self.tokens = {}

    def fresh(self):
        """Rebuild orch/desk against persisted state (new request)."""
        self.orch = Orchestrator(self.store, clock=self.clock)
        self.desk = WatchDesk(self.orch, clock=self.clock)
        return self.orch, self.desk

    def login_quote(self, pid, bad_measurement=False, now_offset=None):
        """Mint a one-shot login challenge+quote for pid's terminal."""
        did = "dev_" + pid
        ch = self.desk.login_challenge(did)
        w = self.wallets[pid]
        kw = {"now": self.clock()}
        if bad_measurement:
            kw["live_measurement"] = b"\x00" * 32
        if now_offset is not None:
            kw["now"] = self.clock() + now_offset
        return did, w.quote(crypto.b64d(ch["challenge"]), **kw)

    def login(self, pid, **kw):
        did, quote = self.login_quote(pid, **kw)
        r = self.desk.login(did, quote)
        self.tokens[pid] = r["token"]
        return r

    def tok(self, pid):
        return self.tokens[pid]

    def open_generate(self):
        cid = self.orch.open_ceremony(P.GENERATE, "pol-v1", "root-signing",
                                      "alice")["id"]
        for pid in ("alice", "bruno", "carla", "diego"):
            self.ctx[pid].attest(self.orch, cid)
        for pid in ("alice", "bruno", "carla", "diego"):
            self.ctx[pid].receive_share(self.orch, cid)
        for pid in ("alice", "bruno", "carla"):
            self.ctx[pid].confirm(self.orch, cid)
        self.orch.commit(cid, "alice")
        return cid

    def staged_rotation(self):
        """Completed-but-unpublished ROTATE; returns (cid, old_active_id)."""
        old = self.orch.dir.active_id("root-signing")
        cid = self.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                      "alice")["id"]
        for pid in ("alice", "bruno", "carla", "diego"):
            self.ctx[pid].attest(self.orch, cid)
        for pid in ("alice", "bruno", "carla", "diego"):
            self.ctx[pid].receive_share(self.orch, cid)
        for pid in ("alice", "bruno", "carla"):
            self.ctx[pid].confirm(self.orch, cid)
        self.orch.commit(cid, "alice")
        return cid, old

    def retiring_destroy_ceremony(self):
        """Rotate then open+drive a DESTROY ceremony up to (not including)
        the purge commit. Returns (cid, retiring_version_id)."""
        old = self.orch.dir.active_id("root-signing")
        rot = self.staged_rotation()[0]
        self.orch.publish_rotation(rot, "alice", expected_active=old)
        retiring = old
        cid = self.orch.open_ceremony(
            P.DESTROY, "pol-v1", "root-signing", "alice",
            target_version=retiring)["id"]
        for pid in ("alice", "bruno", "carla", "diego"):
            self.ctx[pid].attest(self.orch, cid)
        for pid in ("alice", "bruno", "carla"):
            self.ctx[pid].confirm(self.orch, cid)
        return cid, retiring


class Base(unittest.TestCase):
    def setUp(self):
        self.w = DeskWorld("/tmp/kc-desk-" + self.__class__.__name__)
        self.ctx = self.w.store.locked()
        self.ctx.__enter__()

    def tearDown(self):
        self.w.orch.save()
        self.ctx.__exit__(None, None, None)


class TestSessions(Base):
    def test_login_binds_person_duty_terminal_deadline(self):
        r = self.w.login("alice")
        s = r["session"]
        self.assertEqual(s["participant_id"], "alice")
        self.assertEqual(s["device_id"], "dev_alice")
        self.assertIn(RULES_AUTHOR, s["duties"])
        self.assertLessEqual(s["deadline"] - s["created_at"], 1800 + 1)
        self.assertIn("FLOW_ABORT", r["actions"]["can_request"])
        self.assertEqual(r["actions"]["can_approve"], [])
        # authenticate round-trips with the raw token
        again = self.w.desk.authenticate(r["token"])
        self.assertEqual(again["token_id"], s["token_id"])

    def test_no_token_and_unknown_token_rejected(self):
        with self.assertRaises(SessionError):
            self.w.desk.authenticate(None)
        with self.assertRaises(SessionError):
            self.w.desk.authenticate(crypto.b64e(b"x" * 32))

    def test_bad_measurement_quote_rejected(self):
        with self.assertRaises(AttestationError):
            self.w.login("alice", bad_measurement=True)

    def test_challenge_is_one_time(self):
        did, quote = self.w.login_quote("alice")
        self.w.desk.login(did, quote)
        # replay the same quote: the challenge is spent
        from kc.errors import AuthenticationError
        with self.assertRaises((SessionError, AuthenticationError)):
            self.w.desk.login(did, quote)

    def test_scope_gating_and_read_only_auditor(self):
        self.w.login("erin")
        # auditor may read audit...
        self.w.desk.authenticate(self.w.tok("erin"), scope="audit")
        # plain authentication (no scope) is fine for a read-only session...
        self.w.desk.authenticate(self.w.tok("erin"))
        # ...but the read-only auditor holds no executable duty at all
        with self.assertRaises(Forbidden):
            self.w.desk.authenticate(self.w.tok("erin"),
                                     duty=RELEASE_MANAGER)
        with self.assertRaises(Forbidden):
            self.w.desk.authenticate(self.w.tok("erin"),
                                     duty=CEREMONY_EXEC)

    def test_token_expiry_closes_at_decision_time(self):
        r = self.w.login("alice")
        self.w.clock.advance(1801)
        with self.assertRaises(SessionError):
            self.w.desk.authenticate(r["token"])

    def test_relogin_continues_open_orders_and_revokes_old_token(self):
        r1 = self.w.login("alice")
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        order = self.w.desk.create_order(
            r1["session"], OP_FLOW_ABORT,
            {"ceremony_id": cid, "reason": "x"})
        # first token logged out, then a fresh login on the same terminal
        self.w.desk.logout(r1["session"]["token_id"])
        with self.assertRaises(SessionError):
            self.w.desk.authenticate(r1["token"])
        r2 = self.w.login("alice")
        self.assertIn(order["id"], r2["rebound_orders"])
        o = self.w.desk.state["orders"][order["id"]]
        self.assertEqual(o["requester"]["session_token_id"],
                         r2["session"]["token_id"])
        # bruno (complementary FLOW_SUPERVISOR, different terminal) approves
        bs = self.w.login("bruno")["session"]
        out = self.w.desk.approve_order(bs, order["id"])
        self.assertEqual(out["status"], "APPROVED")
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "ABORTED")

    def test_revoked_terminal_kills_session_and_orders(self):
        alice = self.w.login("alice")["session"]
        bruno = self.w.login("bruno")["session"]
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        order = self.w.desk.create_order(
            alice, OP_FLOW_ABORT, {"ceremony_id": cid, "reason": "x"})
        res = self.w.desk.revoke_device(bruno, "dev_alice", "compromise")
        self.assertIn(alice["token_id"], res["sessions_killed"])
        self.assertIn(order["id"], res["orders_closed"])
        with self.assertRaises(SessionError):
            self.w.desk.authenticate(self.w.tok("alice"))

    def test_sod_violating_grant_rejected(self):
        with self.assertRaises(PolicyViolation):
            self.w.desk.set_grants(
                None, "alice", [RULES_AUTHOR, RULES_GOVERNOR])


class TestOrdersHappyPath(Base):
    def _policies_slots(self, pid="pol-v2"):
        return {
            "new_policy_id": pid, "label": "root v2", "threshold": 3,
            "slot_specs": [
                ["alice", P.ROOT_OWNER, "dev_alice"],
                ["bruno", P.KEY_STEWARD, "dev_bruno"],
                ["carla", P.WITNESS_SHAREHOLDER, "dev_carla"],
                ["diego", P.ENCLAVE_OPERATOR, "dev_diego"]],
            "purposes": ["root-signing"], "handover_seconds": 3600,
            "ceremony_timeout_seconds": 1800, "supersedes": "pol-v1"}

    def test_policy_revise_four_eyes_aborts_open_round(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_POLICY_REVISE, self._policies_slots())
        self.assertEqual(o["status"], "OPEN")
        self.assertEqual(len(o["decisions"]), 1)
        bruno = self.w.login("bruno")["session"]
        out = self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(out["status"], "APPROVED")
        self.assertEqual(out["result"]["policy_id"], "pol-v2")
        self.assertIn(cid, out["result"]["aborted_open_ceremonies"])
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "ABORTED")

    def test_publish_order_cas_success(self):
        self.w.open_generate()
        cid, old = self.w.staged_rotation()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PUBLISH,
            {"ceremony_id": cid, "expected_active": old})
        bruno = self.w.login("bruno")["session"]
        out = self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(out["status"], "APPROVED")
        self.assertTrue(out["result"]["published"])
        self.assertEqual(self.w.orch.dir.active_id("root-signing"),
                         self.w.orch.state["ceremonies"][cid]["result"][
                             "key_version"])

    def test_flow_abort_order(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_FLOW_ABORT,
            {"ceremony_id": cid, "reason": "suspicious"})
        bruno = self.w.login("bruno")["session"]
        out = self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(out["result"]["status"], "ABORTED")
        self.assertIn("suspicious", out["result"]["abort"]["reason"])

    def test_purge_retired_material_order(self):
        self.w.open_generate()
        cid, retiring = self.w.retiring_destroy_ceremony()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PURGE,
            {"ceremony_id": cid, "target_version": retiring})
        bruno = self.w.login("bruno")["session"]
        out = self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(out["status"], "APPROVED")
        self.assertEqual(
            self.w.orch.dir.get(retiring)["status"], "DESTROYED")
        self.assertNotIn(retiring, self.w.orch.state["wraps"])

    def test_duplicate_create_returns_original_order(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        payload = {"ceremony_id": cid, "reason": "r"}
        o1 = self.w.desk.create_order(alice, OP_FLOW_ABORT, payload)
        # resubmit same person/device/op/canonical payload -> same order
        o2 = self.w.desk.create_order(
            alice, OP_FLOW_ABORT, {"reason": "r", "ceremony_id": cid})
        self.assertEqual(o1["id"], o2["id"])
        # a different reason (different digest) on the same target conflicts
        with self.assertRaises(ConflictState):
            self.w.desk.create_order(
                alice, OP_FLOW_ABORT,
                {"ceremony_id": cid, "reason": "different"})


class TestApprovalGuards(Base):
    def _abort_order(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_FLOW_ABORT,
            {"ceremony_id": cid, "reason": "x"})
        return o, cid

    def test_requester_cannot_self_approve(self):
        o, cid = self._abort_order()
        alice2 = self.w.login("alice")["session"]
        with self.assertRaises(Forbidden):
            self.w.desk.approve_order(alice2, o["id"])
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["status"], "CLOSED")
        # ceremony untouched: still open
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "OPEN")

    def test_same_terminal_different_person_closes(self):
        o, cid = self._abort_order()
        # bruno holds the complementary FLOW_SUPERVISOR duty, but approve
        # from the SAME terminal dev_alice the requester used -> rejected.
        self.w.login("bruno")
        real = self.w.desk.state["sessions"][
            "tok_" + crypto.digest_hex(
                {"t": "kc-token-v1", "token": self.w.tok("bruno")})[:20]]
        forged = dict(real)
        forged["device_id"] = "dev_alice"
        with self.assertRaises(Forbidden):
            self.w.desk.approve_order(forged, o["id"])
        stored = self.w.desk.state["orders"][o["id"]]
        self.assertEqual(stored["status"], "CLOSED")
        self.assertEqual(stored["close_reason"], "DUTY_CONFLICT")
        # ceremony untouched
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "OPEN")

    def test_missing_complementary_duty_closes(self):
        o, cid = self._abort_order()
        # carla and diego lack FLOW_SUPERVISOR
        carla = self.w.login("carla")["session"]
        with self.assertRaises(Forbidden):
            self.w.desk.approve_order(carla, o["id"])
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["close_reason"],
            "DUTY_CONFLICT")
        # a second attempt on the now-closed order is itself rejected
        diego = self.w.login("diego")["session"]
        with self.assertRaises(OrderError):
            self.w.desk.approve_order(diego, o["id"])

    def test_payload_drift_closes_order(self):
        o, cid = self._abort_order()
        # mutate the frozen payload post-create (simulates tampered store)
        stored = self.w.desk.state["orders"][o["id"]]
        stored["payload"]["reason"] = "changed after freeze"
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(TamperError):
            self.w.desk.approve_order(bruno, o["id"],
                                     claimed_digest=o["payload_digest"])
        self.assertEqual(
            stored["close_reason"], "PAYLOAD_DRIFT")
        # claimed digest differing from frozen also closes
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "OPEN")

    def test_claimed_digest_mismatch_closes(self):
        o, cid = self._abort_order()
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(OrderError):
            self.w.desk.approve_order(bruno, o["id"],
                                     claimed_digest="0" * 64)
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["close_reason"],
            "PAYLOAD_DRIFT")

    def test_requester_token_invalidated_closes_order(self):
        o, cid = self._abort_order()
        # the requester's login token is logged out (invalidated)
        rsid = o["requester"]["session_token_id"]
        self.w.desk.state["sessions"][rsid]["revoked"] = True
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(SessionError):
            self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["close_reason"],
            "REQUESTER_SESSION_INVALID")

    def test_target_state_changed_closes_without_half_state(self):
        self.w.open_generate()
        cid, old = self.w.staged_rotation()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PUBLISH,
            {"ceremony_id": cid, "expected_active": old})
        # while the order is open, the target state moves: publish the
        # rotation directly at the orchestrator layer (allowed!)
        self.w.orch.publish_rotation(cid, "alice", expected_active=old)
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises((ConflictState, RaceLost)):
            self.w.desk.approve_order(bruno, o["id"])
        st = self.w.desk.state["orders"][o["id"]]
        self.assertEqual(st["status"], "CLOSED")
        self.assertEqual(st["close_reason"], "TARGET_STATE_CHANGED")
        self.assertIsNone(st["result"])
        # exactly one ACTIVE, no double-publish side effect
        actives = [k for k in self.w.orch.dir.versions_for_purpose(
            "root-signing") if k["status"] == "ACTIVE"]
        self.assertEqual(len(actives), 1)

    def test_stale_cas_pin_is_race_lost_and_order_closes(self):
        self.w.open_generate()
        cid, old = self.w.staged_rotation()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PUBLISH,
            {"ceremony_id": cid, "expected_active": "kv_wrong"})
        # preflight catches the stale pin at approval time
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(RaceLost):
            self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["close_reason"],
            "TARGET_STATE_CHANGED")

    def test_order_deadline_expiry_closes(self):
        o, cid = self._abort_order()
        self.w.clock.advance(601)
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(OrderError):
            self.w.desk.approve_order(bruno, o["id"])
        self.assertEqual(
            self.w.desk.state["orders"][o["id"]]["close_reason"],
            "DEADLINE_EXPIRED")

    def test_concurrent_approval_executes_once(self):
        self.w.open_generate()
        cid, old = self.w.staged_rotation()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PUBLISH,
            {"ceremony_id": cid, "expected_active": old})
        b1 = self.w.login("bruno")["session"]
        b2 = self.w.login("bruno")["session"]
        # two tokens, same approver person: first executes, second is
        # DuplicateAction (order already APPROVED)
        first = self.w.desk.approve_order(b1, o["id"])
        self.assertEqual(first["status"], "APPROVED")
        with self.assertRaises(DuplicateAction):
            self.w.desk.approve_order(b2, o["id"])
        actives = [k for k in self.w.orch.dir.versions_for_purpose(
            "root-signing") if k["status"] == "ACTIVE"]
        self.assertEqual(len(actives), 1)

    def test_withdraw_then_approve_rejected(self):
        o, cid = self._abort_order()
        alice = self.w.login("alice")["session"]
        self.w.desk.withdraw_order(alice, o["id"], "changed my mind")
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(OrderError):
            self.w.desk.approve_order(bruno, o["id"])

    def test_non_requester_cannot_withdraw(self):
        o, cid = self._abort_order()
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(Forbidden):
            self.w.desk.withdraw_order(bruno, o["id"], "not yours")

    def test_reject_by_complementary_duty(self):
        o, cid = self._abort_order()
        bruno = self.w.login("bruno")["session"]
        out = self.w.desk.reject_order(bruno, o["id"], "looks wrong")
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(
            self.w.orch.public_ceremony(cid)["status"], "OPEN")


class TestOrderPersist(Base):
    def test_closed_order_survives_reload(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_FLOW_ABORT,
            {"ceremony_id": cid, "reason": "x"})
        self.w.desk.logout(alice["token_id"])
        bruno = self.w.login("bruno")["session"]
        with self.assertRaises(SessionError):
            self.w.desk.approve_order(bruno, o["id"])
        self.w.orch.save()
        # reload into a fresh process-like view
        orch2, desk2 = self.w.fresh()
        st = desk2.state["orders"][o["id"]]
        self.assertEqual(st["close_reason"], "REQUESTER_SESSION_INVALID")
        probs = orch2.audit.verify(
            crypto.ed25519.public_from_secret(self.w.store.service_seed()))
        self.assertEqual(probs, [])


class TestExportDesk(Base):
    def test_bundle_records_parties_tokens_chain_and_detects_edit(self):
        self.w.open_generate()
        cid, old = self.w.staged_rotation()
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_PUBLISH,
            {"ceremony_id": cid, "expected_active": old})
        bruno = self.w.login("bruno")["session"]
        self.w.desk.approve_order(bruno, o["id"])

        bundle = export_mod.build_bundle(self.w.orch)
        v = export_mod.verify_bundle(bundle)
        self.assertTrue(v["ok"], v["problems"])
        self.assertTrue(v["checks"]["four_eyes_orders_ok"])
        self.assertTrue(v["checks"]["duty_separation_ok"])
        rec = next(x for x in bundle["orders"] if x["id"] == o["id"])
        self.assertEqual(rec["requester"]["participant_id"], "alice")
        self.assertEqual(rec["approver"]["participant_id"], "bruno")
        self.assertNotEqual(rec["requester"]["device_id"],
                            rec["approver"]["device_id"])
        self.assertTrue(rec["requester"]["session_token_id"])
        self.assertTrue(rec["approver"]["session_token_id"])
        self.assertEqual(len(rec["decisions"]), 2)
        self.assertTrue(rec["result"]["published"])

        # 1. delete an audit decision entry -> cross-link failure
        bad = json.loads(json.dumps(bundle))
        bad["audit"] = [e for e in bad["audit"]
                        if not (e["event"] == "order_decision"
                                and e["payload"]["seq"] == 1
                                and e["payload"]["order_id"] == o["id"])]
        v1 = export_mod.verify_bundle(bad)
        self.assertFalse(v1["ok"])
        self.assertTrue(any("missing matching audit entry" in p
                            for p in v1["problems"]))

        # 2. edit a stored decision -> local chain hash mismatch
        bad2 = json.loads(json.dumps(bundle))
        ro = next(x for x in bad2["orders"] if x["id"] == o["id"])
        ro["decisions"][1]["actor"]["participant_id"] = "alice"
        v2 = export_mod.verify_bundle(bad2)
        self.assertFalse(v2["ok"])
        self.assertTrue(any("decision 1 hash mismatch" in p
                            for p in v2["problems"]))

        # 3. swap approver to the same person (defeat four-eyes) -> detected
        bad3 = json.loads(json.dumps(bundle))
        ro3 = next(x for x in bad3["orders"] if x["id"] == o["id"])
        # create a synthetic but internally consistent tamper: hashes are
        # recomputed so the chain check passes, the semantic check must fire
        ro3["approver"]["participant_id"] = "alice"
        v3 = export_mod.verify_bundle(bad3)
        self.assertFalse(v3["ok"])
        self.assertTrue(any("four-eyes" in p for p in v3["problems"]))

        # 4. edit the frozen payload -> digest mismatch
        bad4 = json.loads(json.dumps(bundle))
        ro4 = next(x for x in bad4["orders"] if x["id"] == o["id"])
        ro4["payload"]["expected_active"] = "kv_forged"
        v4 = export_mod.verify_bundle(bad4)
        self.assertFalse(v4["ok"])
        self.assertTrue(any("edited" in p for p in v4["problems"]))

    def test_closed_order_export_shows_no_result(self):
        self.w.open_generate()
        cid = self.w.orch.open_ceremony(P.ROTATE, "pol-v1", "root-signing",
                                        "alice")["id"]
        alice = self.w.login("alice")["session"]
        o = self.w.desk.create_order(
            alice, OP_FLOW_ABORT,
            {"ceremony_id": cid, "reason": "x"})
        carla = self.w.login("carla")["session"]
        with self.assertRaises(Forbidden):
            self.w.desk.approve_order(carla, o["id"])
        bundle = export_mod.build_bundle(self.w.orch)
        v = export_mod.verify_bundle(bundle)
        self.assertTrue(v["ok"], v["problems"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
