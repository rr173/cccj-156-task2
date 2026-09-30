"""Watchstander desk: terminal-attested sessions and four-eyes authorization.

This module is the policy layer *in front of* the ceremony orchestrator. The
orchestrator library itself stays directly callable (operational tooling,
scripts and tests use it with no HTTP session); the HTTP console, however,
admits no state-changing lifecycle operation without going through here.

Three objects live in this layer:

  * Duty grants
        A participant holds one or more operational *duties* (separate from
        the shareholding roles on a ceremony policy). Every sensitive action
        names the duty that may *request* it and the *complementary* duty
        that may *approve* it. One person can therefore never self-approve:
        the complementary pairs are disjoint per grant by construction.

  * Sessions (login tokens)
        Login is a fresh device attestation quote, exactly like a ceremony
        quote (identity-key signature over a server nonce, the live
        measurement, the sealing key and a timestamp). The resulting token is
        bound to (person, duty snapshot, device, attestation deadline). A
        revoked device, a stale quote or an expired deadline invalidates the
        token. Re-login on the same (person, device) continues open orders.

  * Authorization orders
        A rule change, a flow abort, a rotation publish or a purge of retired
        material first creates an order that freezes the *canonical payload
        digest* and a deadline. A second person on a *different* device,
        holding the complementary duty, then approves. Approval re-validates
        everything (tokens, terminals, digest, target state) inside the same
        store-lock transaction as the execution, so a concurrent approval
        runs at most once and a failed validation closes the order without
        ever touching target state ("no half-finished artifacts").

Every order carries a decision chain; each decision (create/approve/reject/
withdraw/close) is hash-linked over the prior decision and the full order
record, and each is mirrored as a service-signed audit entry.
"""

from __future__ import annotations

import os
import time

from . import crypto, ed25519
from .attestation import EnrolledDevice, verify_quote
from . import policy as pol
from .errors import (
    AttestationError, AuthenticationError, CeremonyError, ConflictState,
    DuplicateAction, Forbidden, NotFound, OrderError, PolicyViolation,
    RaceLost, SessionError, TamperError,
)

# ---------------------------------------------------------------------------
# duties: complementary pairs + action catalogue
# ---------------------------------------------------------------------------

RULES_AUTHOR = "RULES_AUTHOR"           # drafts policy/rule changes
RULES_GOVERNOR = "RULES_GOVERNOR"       # approves rule changes
FLOW_CONTROLLER = "FLOW_CONTROLLER"     # terminates running flows
FLOW_SUPERVISOR = "FLOW_SUPERVISOR"     # approves flow termination
RELEASE_MANAGER = "RELEASE_MANAGER"     # publishes a new generation
RELEASE_VERIFIER = "RELEASE_VERIFIER"   # approves a publish
MATERIAL_CUSTODIAN = "MATERIAL_CUSTODIAN"  # requests retired-material purge
MATERIAL_AUDITOR = "MATERIAL_AUDITOR"   # approves the purge
CEREMONY_EXEC = "CEREMONY_EXEC"         # drives ordinary ceremony steps
KEYS_READ = "KEYS_READ"                 # read keys/purposes
AUDIT_READ = "AUDIT_READ"               # read audit/export

ALL_DUTIES = (
    RULES_AUTHOR, RULES_GOVERNOR, FLOW_CONTROLLER, FLOW_SUPERVISOR,
    RELEASE_MANAGER, RELEASE_VERIFIER, MATERIAL_CUSTODIAN, MATERIAL_AUDITOR,
    CEREMONY_EXEC, KEYS_READ, AUDIT_READ,
)

# The complementary duty of the requester is the only duty that may approve.
# A single grant may never contain both sides of a pair (separation of duty).
COMPLEMENTARY = {
    RULES_AUTHOR: RULES_GOVERNOR,
    FLOW_CONTROLLER: FLOW_SUPERVISOR,
    RELEASE_MANAGER: RELEASE_VERIFIER,
    MATERIAL_CUSTODIAN: MATERIAL_AUDITOR,
}
_SOD_PAIRS = [(a, b) for a, b in COMPLEMENTARY.items()]

# Guarded actions: op -> (requester duty, complementary approver duty)
OP_POLICY_REVISE = "POLICY_REVISE"
OP_FLOW_ABORT = "FLOW_ABORT"
OP_PUBLISH = "PUBLISH"
OP_PURGE = "OP_PURGE"

ACTION_CATALOGUE = {
    OP_POLICY_REVISE: (RULES_AUTHOR, RULES_GOVERNOR),
    OP_FLOW_ABORT: (FLOW_CONTROLLER, FLOW_SUPERVISOR),
    OP_PUBLISH: (RELEASE_MANAGER, RELEASE_VERIFIER),
    OP_PURGE: (MATERIAL_CUSTODIAN, MATERIAL_AUDITOR),
}

# read scopes granted by each duty (query admission is by duty)
_SCOPES = {
    RULES_AUTHOR: ("policies", "ceremonies", "keys", "participants"),
    RULES_GOVERNOR: ("policies", "ceremonies", "keys", "participants",
                     "audit"),
    FLOW_CONTROLLER: ("ceremonies", "policies", "keys"),
    FLOW_SUPERVISOR: ("ceremonies", "policies", "keys", "audit"),
    RELEASE_MANAGER: ("ceremonies", "keys", "policies"),
    RELEASE_VERIFIER: ("ceremonies", "keys", "policies", "audit"),
    MATERIAL_CUSTODIAN: ("keys", "ceremonies", "policies"),
    MATERIAL_AUDITOR: ("keys", "ceremonies", "policies", "audit"),
    CEREMONY_EXEC: ("ceremonies", "policies", "keys", "participants"),
    KEYS_READ: ("keys", "ceremonies", "policies"),
    AUDIT_READ: ("audit", "keys", "ceremonies", "policies", "participants"),
}

# token lifetime bounds
SESSION_TTL_SECONDS = 1800          # hard cap
QUOTE_VALIDITY_SECONDS = 3600       # terminal attestation horizon
ORDER_TTL_SECONDS = 600
CHALLENGE_TTL_SECONDS = 120

# order lifecycle
O_OPEN = "OPEN"
O_APPROVED = "APPROVED"
O_REJECTED = "REJECTED"
O_WITHDRAWN = "WITHDRAWN"
O_CLOSED = "CLOSED"
TERMINAL_ORDER_STATES = (O_APPROVED, O_REJECTED, O_WITHDRAWN, O_CLOSED)


def _id(prefix: str) -> str:
    return f"{prefix}_{os.urandom(10).hex()}"


def canonical_payload(op: str, payload: dict) -> dict:
    """Project a request payload onto the fields meaningful for an op and
    sort/canonicalize it so two requests for the same change compare equal."""
    keys = _OP_FIELDS[op]
    return {k: _canon(payload.get(k)) for k in keys}


def _canon(v):
    if isinstance(v, dict):
        return {k: _canon(v[k]) for k in sorted(v)}
    if isinstance(v, (list, tuple)):
        return [_canon(x) for x in v]
    return v


_OP_FIELDS = {
    OP_POLICY_REVISE: ("new_policy_id", "label", "threshold", "slot_specs",
                       "purposes", "handover_seconds",
                       "ceremony_timeout_seconds", "supersedes"),
    OP_FLOW_ABORT: ("ceremony_id", "reason"),
    OP_PUBLISH: ("ceremony_id", "expected_active"),
    OP_PURGE: ("ceremony_id", "target_version"),
}


def payload_digest(op: str, canon: dict) -> str:
    return crypto.digest_hex({"t": "kc-order-payload-v1", "op": op,
                              "payload": canon})


def scopes_for(duties) -> set[str]:
    out: set[str] = set()
    for d in duties:
        out.update(_SCOPES.get(d, ()))
    return out


class WatchDesk:
    """Duty grants, terminal-attested sessions and authorization orders.

    Constructed per request inside ``store.locked()`` alongside an
    Orchestrator; shares the same state dict and audit log.
    """

    def __init__(self, orch, clock=time.time,
                 session_ttl: int = SESSION_TTL_SECONDS,
                 order_ttl: int = ORDER_TTL_SECONDS):
        self.orch = orch
        self.state = orch.state
        self.audit = orch.audit
        self.clock = clock
        self.session_ttl = session_ttl
        self.order_ttl = order_ttl

    # ======================================================================
    # duty grants
    # ======================================================================
    def grants_of(self, participant_id: str) -> tuple[str, ...]:
        return tuple(self.state["duty_grants"].get(participant_id, []))

    def set_grants(self, actor_sid: str | None, participant_id: str,
                   duties: list[str]) -> dict:
        """Administrative grant change. The *first* grant is bootstrapped
        without an actor (bootstrap process); later changes require the
        DUTY_ADMIN-capable RULES_GOVERNOR duty."""
        bad = [d for d in duties if d not in ALL_DUTIES]
        if bad:
            raise PolicyViolation(f"unknown duties: {bad}")
        duties = sorted(set(duties))
        for a, b in _SOD_PAIRS:
            if a in duties and b in duties:
                raise PolicyViolation(
                    f"separation of duties: one person cannot hold both "
                    f"{a} and {b} (requester/approver of the same action)")
        if participant_id not in self.state["participants"]:
            raise NotFound(f"participant {participant_id} not enrolled")
        prev = self.grants_of(participant_id)
        self.state["duty_grants"][participant_id] = duties
        self.audit.append("duty_grants_changed",
                          {"actor_session": actor_sid,
                           "participant_id": participant_id,
                           "duties": duties, "previous": list(prev)})
        return {"participant_id": participant_id, "duties": duties,
                "previous": list(prev)}

    # ======================================================================
    # terminal attestation -> login session
    # ======================================================================
    def login_challenge(self, device_id: str) -> dict:
        dev = self._enrolled(device_id)
        if dev.revoked:
            raise AttestationError(f"device {device_id} is revoked")
        nonce = crypto.b64e(os.urandom(32))
        self.state["login_challenges"][device_id] = {
            "nonce": nonce, "ts": self.clock()}
        self.audit.append("login_challenge_issued",
                          {"device_id": device_id,
                           "participant_id": dev.participant_id})
        return {"device_id": device_id, "challenge": nonce}

    def login(self, device_id: str, quote: dict) -> dict:
        dev = self._enrolled(device_id)
        if dev.revoked:
            raise AttestationError(f"device {device_id} is revoked")
        ch = self.state["login_challenges"].pop(device_id, None)
        if ch is None:
            raise AuthenticationError("no outstanding login challenge; "
                                      "request one first")
        if self.clock() - ch["ts"] > CHALLENGE_TTL_SECONDS:
            raise AuthenticationError("login challenge expired")
        verify_quote(quote, dev, crypto.b64d(ch["nonce"]),
                     now=self.clock())
        if quote.get("device_id") != device_id:
            raise AttestationError("quote device mismatch")
        pid = dev.participant_id
        duties = list(self.grants_of(pid))
        now = self.clock()
        deadline = min(now + self.session_ttl,
                       now + QUOTE_VALIDITY_SECONDS)
        token = crypto.b64e(os.urandom(32))
        token_id = "tok_" + crypto.digest_hex({"t": "kc-token-v1",
                                               "token": token})[:20]
        session = {
            "token_id": token_id,
            "participant_id": pid,
            "name": self.state["participants"][pid]["name"],
            "role": self.state["participants"][pid]["role"],
            "duties": duties,             # frozen at login
            "device_id": device_id,
            "measurement": quote["measurement"],
            "seal_pub": quote["seal_pub"],
            "quote_ts": quote["ts"],
            "created_at": now,
            "deadline": deadline,
            "revoked": False,
            "logout_at": None,
        }
        self.state["sessions"][token_id] = session
        self.audit.append("session_opened",
                          {"token_id": token_id, "participant_id": pid,
                           "device_id": device_id, "duties": duties,
                           "deadline": deadline})
        # Re-login continues outstanding work: re-bind the person's OPEN
        # orders on this device to the new token (decision time still
        # re-validates the frozen requester binding).
        rebound = []
        for o in self.state["orders"].values():
            if o["status"] == O_OPEN and \
                    o["requester"]["participant_id"] == pid and \
                    o["requester"]["device_id"] == device_id:
                o["requester"]["session_token_id"] = token_id
                rebound.append(o["id"])
        return {"token": token, "session": self.public_session(session),
                "scopes": sorted(scopes_for(duties)),
                "actions": self.action_view(session),
                "rebound_orders": rebound}

    def logout(self, token_id: str) -> dict:
        s = self.state["sessions"].get(token_id)
        if s is None:
            raise SessionError("unknown session")
        s["logout_at"] = self.clock()
        s["revoked"] = True
        self.audit.append("session_closed",
                          {"token_id": token_id,
                           "participant_id": s["participant_id"],
                           "reason": "logout"})
        return {"ok": True, "token_id": token_id}

    def _enrolled(self, device_id: str) -> EnrolledDevice:
        d = self.state["devices"].get(device_id)
        if d is None:
            raise NotFound(f"device {device_id} not enrolled")
        return EnrolledDevice.from_dict(d)

    # ---- session validation ---------------------------------------------
    def authenticate(self, token: str | None, scope: str | None = None,
                     duty: str | None = None) -> dict:
        """Validate a bearer token and return the live session record.

        A session is valid only while its deadline is in the future, it has
        not been logged out/revoked, and its bound device is still enrolled
        and unrevoked with the same measurement/sealing key.
        """
        if not token:
            raise SessionError("missing bearer token")
        token_id = "tok_" + crypto.digest_hex({"t": "kc-token-v1",
                                               "token": token})[:20]
        s = self.state["sessions"].get(token_id)
        if s is None:
            raise SessionError("unknown token")
        if s.get("revoked") or s.get("logout_at"):
            raise SessionError("session logged out")
        if self.clock() >= s["deadline"]:
            raise SessionError("session past attestation deadline; re-login")
        d = self.state["devices"].get(s["device_id"])
        if d is None:
            raise SessionError("bound terminal no longer enrolled")
        if d.get("revoked"):
            raise SessionError("bound terminal was revoked")
        if d["measurement"] != s["measurement"]:
            raise SessionError("terminal measurement changed since login")
        if d["seal_pub"] != s["seal_pub"]:
            raise SessionError("terminal sealing key changed since login")
        if d["participant_id"] != s["participant_id"]:
            raise SessionError("terminal reassigned since login")
        # duties can be narrowed administratively after login
        effective = [x for x in s["duties"]
                     if x in self.grants_of(s["participant_id"])]
        if duty is not None and duty not in effective:
            raise Forbidden(
                f"duty {duty} required (session duties at login: "
                f"{s['duties']})")
        if scope is not None and scope not in scopes_for(effective):
            raise Forbidden(f"scope {scope} required for this query")
        return s

    def revoke_device(self, admin_session: dict, device_id: str,
                      reason: str) -> dict:
        """Revoke a registered terminal. Kills every session bound to it and
        closes every OPEN order whose requester or bound terminal is that
        device (the attestation constraint no longer holds)."""
        dev = self.state["devices"].get(device_id)
        if dev is None:
            raise NotFound(f"device {device_id} not enrolled")
        dev["revoked"] = True
        killed = []
        for s in self.state["sessions"].values():
            if s["device_id"] == device_id and not s.get("revoked"):
                s["revoked"] = True
                s["logout_at"] = self.clock()
                killed.append(s["token_id"])
        closed = self._close_orders_for_device(device_id, "TERMINAL_REVOKED",
                                               admin_session["token_id"])
        self.audit.append("device_revoked",
                          {"actor_session": admin_session["token_id"],
                           "actor": admin_session["participant_id"],
                           "device_id": device_id, "reason": reason,
                           "sessions_killed": killed,
                           "orders_closed": closed})
        return {"device_id": device_id, "revoked": True,
                "sessions_killed": killed, "orders_closed": closed}

    # ======================================================================
    # authorization orders
    # ======================================================================
    def create_order(self, session: dict, op: str, payload: dict) -> dict:
        if op not in ACTION_CATALOGUE:
            raise PolicyViolation(f"unknown guarded action {op}")
        requester_duty, approver_duty = ACTION_CATALOGUE[op]
        if requester_duty not in self._effective_duties(session):
            raise Forbidden(
                f"only duty {requester_duty} may request {op} "
                f"(session: {session['duties']})")
        canon = canonical_payload(op, payload)
        self._validate_create(op, canon)
        digest = payload_digest(op, canon)
        now = self.clock()
        # idempotent re-submit: same person+device+op+open digest returns the
        # original order. A closed order with the same digest is NOT reused;
        # re-submitting opens a fresh one.
        for o in self.state["orders"].values():
            if o["status"] == O_OPEN \
                    and o["op"] == op \
                    and o["requester"]["participant_id"] == \
                    session["participant_id"] \
                    and o["requester"]["device_id"] == session["device_id"] \
                    and o["payload_digest"] == digest:
                return self.public_order(o)
        # one open order per target (per op) prevents digest-distinct racing
        # requests aimed at the same object
        target = self._target_key(op, canon)
        if target:
            for o in self.state["orders"].values():
                if o["status"] == O_OPEN and o["op"] == op \
                        and self._target_key(o["op"], o["payload"]) == target:
                    raise ConflictState(
                        f"an OPEN {op} order {o['id']} already targets "
                        f"{target}; withdraw or wait for it")
        oid = _id("ord")
        o = {
            "id": oid,
            "op": op,
            "payload": canon,
            "payload_digest": digest,
            "deadline": now + self.order_ttl,
            "status": O_OPEN,
            "requester": {
                "participant_id": session["participant_id"],
                "name": session["name"],
                "duty": requester_duty,
                "device_id": session["device_id"],
                "session_token_id": session["token_id"],
            },
            "approver_duty": approver_duty,
            "approver": None,
            "decisions": [],
            "created_at": now,
            "decided_at": None,
            "result": None,
            "close_reason": None,
            "execution_error": None,
        }
        self.state["orders"][oid] = o
        self._decision(o, "CREATE", actor=o["requester"],
                       session_token_id=session["token_id"])
        return self.public_order(o)

    def approve_order(self, approver_session: dict, order_id: str,
                      claimed_digest: str | None = None) -> dict:
        o = self._get(order_id)
        if o["status"] == O_APPROVED:
            raise DuplicateAction(
                f"order {order_id} already approved and executed")
        if o["status"] != O_OPEN:
            raise OrderError(
                f"order {order_id} is {o['status']}, cannot approve")

        # All validation happens BEFORE any state mutation; failure closes
        # the order and raises, so no half-finished artifact is left behind.
        try:
            self._validate_approval(o, approver_session, claimed_digest)
        except (SessionError, Forbidden, OrderError, ConflictState,
                PolicyViolation, AttestationError, RaceLost, NotFound,
                DuplicateAction, AuthenticationError, TamperError):
            raise
        except Exception as e:  # defensive: never execute on a failed check
            self._fail_close(o, "APPROVAL_VALIDATION_FAILED",
                             approver_session, str(e))
            raise

        # Commit the decision first; the store lock serializes concurrent
        # approvers so exactly one reaches execution.
        approver = self._actor(approver_session, o["approver_duty"])
        self._decision(o, "APPROVE", actor=approver,
                       session_token_id=approver_session["token_id"])
        o["status"] = O_APPROVED
        o["decided_at"] = self.clock()
        o["approver"] = approver
        try:
            result = self._execute(o)
        except CeremonyError as e:  # target moved between create and approve
            o["status"] = O_CLOSED
            o["close_reason"] = "TARGET_STATE_CHANGED"
            o["execution_error"] = {"code": e.code, "message": str(e)}
            self._decision(o, "CLOSE", actor=approver,
                           session_token_id=approver_session["token_id"],
                           reason="TARGET_STATE_CHANGED",
                           detail=o["execution_error"])
            self.audit.append("order_closed",
                              {"order_id": o["id"], "op": o["op"],
                               "reason": "TARGET_STATE_CHANGED",
                               "error": o["execution_error"]})
            raise
        o["result"] = {"at": self.clock(), **result}
        self.audit.append("order_executed",
                          {"order_id": o["id"], "op": o["op"],
                           "requester": o["requester"]["participant_id"],
                           "approver": approver["participant_id"],
                           "payload_digest": o["payload_digest"],
                           "result": result})
        return self.public_order(o)

    def reject_order(self, approver_session: dict, order_id: str,
                     reason: str) -> dict:
        o = self._get(order_id)
        if o["status"] != O_OPEN:
            raise OrderError(f"order {order_id} is {o['status']}")
        if o["approver_duty"] not in self._effective_duties(approver_session):
            raise Forbidden(
                f"only duty {o['approver_duty']} may decide on this order")
        if approver_session["participant_id"] == o["requester"]["participant_id"]:
            raise Forbidden("the requester cannot reject their own order")
        actor = self._actor(approver_session, o["approver_duty"])
        o["status"] = O_REJECTED
        o["decided_at"] = self.clock()
        o["approver"] = actor
        o["close_reason"] = "REJECTED"
        self._decision(o, "REJECT", actor=actor,
                       session_token_id=approver_session["token_id"],
                       reason=reason)
        return self.public_order(o)

    def withdraw_order(self, session: dict, order_id: str,
                       reason: str) -> dict:
        o = self._get(order_id)
        if o["status"] != O_OPEN:
            raise OrderError(f"order {order_id} is {o['status']}")
        r = o["requester"]
        if session["participant_id"] != r["participant_id"] or \
                session["device_id"] != r["device_id"]:
            raise Forbidden("only the original requester can withdraw")
        o["status"] = O_WITHDRAWN
        o["decided_at"] = self.clock()
        o["close_reason"] = "WITHDRAWN"
        self._decision(o, "WITHDRAW",
                       actor=self._actor(session, r["duty"]),
                       session_token_id=session["token_id"], reason=reason)
        return self.public_order(o)

    def sweep_expired(self) -> list[str]:
        """Close OPEN orders past their deadline. Called per request so the
        deadline is always enforced without a background worker."""
        now = self.clock()
        closed = []
        for o in list(self.state["orders"].values()):
            if o["status"] == O_OPEN and now > o["deadline"]:
                self._timeout_close(o)
                closed.append(o["id"])
        return closed

    # ---- order validation ------------------------------------------------
    def _effective_duties(self, session: dict) -> list[str]:
        granted = self.grants_of(session["participant_id"])
        return [d for d in session["duties"] if d in granted]

    def _actor(self, session: dict, duty: str) -> dict:
        return {
            "participant_id": session["participant_id"],
            "name": session["name"],
            "duty": duty,
            "device_id": session["device_id"],
            "session_token_id": session["token_id"],
        }

    def _validate_create(self, op: str, p: dict):
        if op == OP_POLICY_REVISE:
            if not p["new_policy_id"] or not p["label"]:
                raise PolicyViolation("new_policy_id and label are required")
            if int(p["threshold"]) < 2:
                raise PolicyViolation("threshold must be >= 2")
            slots = p["slot_specs"]
            if not isinstance(slots, list) or len(slots) < 3:
                raise PolicyViolation("slot_specs must list >= 3 slots")
        elif op == OP_FLOW_ABORT:
            if not p["ceremony_id"]:
                raise PolicyViolation("ceremony_id required")
        elif op == OP_PUBLISH:
            if not p["ceremony_id"] or not p["expected_active"]:
                raise PolicyViolation(
                    "ceremony_id and expected_active (CAS pin) required")
        elif op == OP_PURGE:
            if not p["ceremony_id"] or not p["target_version"]:
                raise PolicyViolation(
                    "ceremony_id and target_version required")

    def _validate_approval(self, o: dict, approver_session: dict,
                           claimed_digest: str | None):
        now = self.clock()
        if now > o["deadline"]:
            self._timeout_close(o)
            raise OrderError(f"order {o['id']} passed its deadline")

        # four-eyes: different person
        if approver_session["participant_id"] == \
                o["requester"]["participant_id"]:
            self._fail_close(o, "DUTY_CONFLICT", approver_session,
                             "requester attempted to self-approve")
            raise Forbidden(
                "four-eyes violation: requester and approver must be "
                "different people")
        # ... different terminal
        if approver_session["device_id"] == o["requester"]["device_id"]:
            self._fail_close(o, "DUTY_CONFLICT", approver_session,
                             "approval from the same terminal")
            raise Forbidden(
                "four-eyes violation: approval must come from a different "
                "terminal")
        # complementary duty (live grant, not just the login snapshot)
        if o["approver_duty"] not in self._effective_duties(approver_session):
            self._fail_close(o, "DUTY_CONFLICT", approver_session,
                             f"approver lacks complementary duty "
                             f"{o['approver_duty']}")
            raise Forbidden(
                f"only duty {o['approver_duty']} may approve this order")

        # requester's token/terminal must STILL be valid (token invalidation
        # or terminal revocation kills the order)
        rsid = o["requester"].get("session_token_id")
        rs = self.state["sessions"].get(rsid)
        if rs is None or rs.get("revoked") or rs.get("logout_at"):
            self._fail_close(o, "REQUESTER_SESSION_INVALID", approver_session,
                             "requester token invalid at approval time")
            raise SessionError("requester session is no longer valid")
        if now >= rs["deadline"]:
            self._fail_close(o, "REQUESTER_SESSION_INVALID", approver_session,
                             "requester token past attestation deadline")
            raise SessionError("requester session expired; re-login needed")
        rdev = self.state["devices"].get(o["requester"]["device_id"])
        if rdev is None or rdev.get("revoked"):
            self._fail_close(o, "TERMINAL_REVOKED", approver_session,
                             "requester terminal revoked")
            raise SessionError("requester terminal revoked")

        # payload drift: what is approved is exactly what was frozen
        if claimed_digest is not None and claimed_digest != o["payload_digest"]:
            self._fail_close(o, "PAYLOAD_DRIFT", approver_session,
                             "approver presented a different digest")
            raise OrderError("presented digest does not match frozen order")
        recomputed = payload_digest(o["op"], o["payload"])
        if recomputed != o["payload_digest"]:
            self._fail_close(o, "PAYLOAD_DRIFT", approver_session,
                             "stored payload no longer hashes to frozen digest")
            raise TamperError("order payload drifted from frozen digest")

        # target state preflight: the object the order was opened against
        # must still be in the expected state. Drift closes the order with
        # TARGET_STATE_CHANGED (no execution, no half-finished state).
        try:
            self._preflight(o)
        except CeremonyError as e:
            self._fail_close(o, "TARGET_STATE_CHANGED", approver_session,
                             f"{e.code}: {e}")
            raise

    def _preflight(self, o: dict):
        p = o["payload"]
        s = self.state
        if o["op"] == OP_POLICY_REVISE:
            if p["new_policy_id"] in s["policies"]:
                raise ConflictState(
                    f"policy {p['new_policy_id']} already exists")
        elif o["op"] == OP_FLOW_ABORT:
            c = s["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound(f"unknown ceremony {p['ceremony_id']}")
            if c["status"] != "OPEN":
                raise ConflictState(
                    f"ceremony {p['ceremony_id']} is {c['status']}, not open")
        elif o["op"] == OP_PUBLISH:
            c = s["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound(f"unknown ceremony {p['ceremony_id']}")
            if c.get("kind") != "ROTATE" or c.get("status") != "COMPLETED":
                raise ConflictState("publish needs a COMPLETED ROTATE ceremony")
            cur = s["purposes"].get(c["purpose"])
            if cur != p["expected_active"]:
                raise RaceLost(
                    f"target state changed: expected ACTIVE "
                    f"{p['expected_active']}, directory says {cur}")
            if c.get("published"):
                raise ConflictState("rotation already published")
        elif o["op"] == OP_PURGE:
            # The purge IS the DESTROY ceremony's commit: at approval time
            # the ceremony must still be OPEN (stage CONFIRMED) and the
            # target version must still hold private material (RETIRING).
            c = s["ceremonies"].get(p["ceremony_id"])
            if c is None:
                raise NotFound(f"unknown ceremony {p['ceremony_id']}")
            if c.get("kind") != "DESTROY":
                raise ConflictState("purge requires a DESTROY ceremony")
            if c.get("status") != "OPEN":
                raise ConflictState(
                    f"DESTROY ceremony is {c.get('status')}; material "
                    "already purged or round aborted")
            kv = s["keys"].get(p["target_version"])
            if kv is None:
                raise NotFound(f"unknown key version {p['target_version']}")
            if kv["status"] == "DESTROYED":
                raise ConflictState("retired material already purged")
            if kv["status"] == "ACTIVE":
                raise PolicyViolation(
                    "cannot purge the ACTIVE version; rotate first")

    # ---- execution (direct orchestrator calls; lock held by caller) ------
    def _execute(self, o: dict) -> dict:
        p = o["payload"]
        orch = self.orch
        requester = o["requester"]["participant_id"]
        approver = o["approver"]["participant_id"]

        if o["op"] == OP_POLICY_REVISE:
            open_before = {cid for cid, c in self.state["ceremonies"].items()
                           if c["status"] == "OPEN"}
            rec = orch.revise_policy(
                p["new_policy_id"], p["label"], int(p["threshold"]),
                [tuple(s) for s in p["slot_specs"]],
                purposes=tuple(p["purposes"] or ["root-signing"]),
                handover_seconds=int(p["handover_seconds"]),
                ceremony_timeout_seconds=int(p["ceremony_timeout_seconds"]),
                supersedes=p.get("supersedes") or None)
            aborted = sorted(
                cid for cid in open_before
                if self.state["ceremonies"][cid]["status"] == "ABORTED")
            return {"policy_id": rec["policy_id"], "version": rec["version"],
                    "aborted_open_ceremonies": aborted,
                    "requester": requester, "approver": approver}

        if o["op"] == OP_FLOW_ABORT:
            view = orch.abort(p["ceremony_id"], requester, p["reason"])
            return {"ceremony_id": p["ceremony_id"],
                    "status": view["status"], "abort": view["abort"],
                    "requester": requester, "approver": approver}

        if o["op"] == OP_PUBLISH:
            view = orch.publish_rotation(
                p["ceremony_id"], requester, p["expected_active"])
            pub = view.get("published")
            return {"ceremony_id": p["ceremony_id"], "published": pub,
                    "requester": requester, "approver": approver}

        if o["op"] == OP_PURGE:
            view = orch.commit(p["ceremony_id"], requester,
                               expected_active=p["target_version"])
            return {"ceremony_id": p["ceremony_id"],
                    "result": view["result"], "stage": view["stage"],
                    "requester": requester, "approver": approver}

        raise PolicyViolation(f"cannot execute op {o['op']}")

    # ---- closing helpers -------------------------------------------------
    def _fail_close(self, o: dict, reason: str, approver_session: dict,
                    detail: str):
        o["status"] = O_CLOSED
        o["decided_at"] = self.clock()
        o["close_reason"] = reason
        o["execution_error"] = {"detail": detail}
        self._decision(o, "CLOSE",
                       actor=self._actor(approver_session,
                                         o["approver_duty"]),
                       session_token_id=approver_session["token_id"],
                       reason=reason, detail=detail)
        self.audit.append("order_closed",
                          {"order_id": o["id"], "op": o["op"], "reason": reason,
                           "detail": detail,
                           "by": approver_session["participant_id"]})

    def _timeout_close(self, o: dict):
        o["status"] = O_CLOSED
        o["decided_at"] = self.clock()
        o["close_reason"] = "DEADLINE_EXPIRED"
        self._decision(o, "CLOSE", actor=None,
                       session_token_id=None, reason="DEADLINE_EXPIRED")
        self.audit.append("order_closed",
                          {"order_id": o["id"], "op": o["op"],
                           "reason": "DEADLINE_EXPIRED"})

    def _close_orders_for_device(self, device_id: str, reason: str,
                                 actor_token_id: str | None) -> list[str]:
        closed = []
        for o in self.state["orders"].values():
            if o["status"] != O_OPEN:
                continue
            if o["requester"]["device_id"] == device_id:
                o["status"] = O_CLOSED
                o["decided_at"] = self.clock()
                o["close_reason"] = reason
                self._decision(o, "CLOSE", actor=None,
                               session_token_id=actor_token_id, reason=reason)
                self.audit.append("order_closed",
                                  {"order_id": o["id"], "op": o["op"],
                                   "reason": reason, "device_id": device_id})
                closed.append(o["id"])
        return closed

    # ---- decision chain --------------------------------------------------
    def _decision(self, o: dict, kind: str, actor: dict | None,
                  session_token_id: str | None, reason: str | None = None,
                  detail: str | None = None) -> dict:
        prev = o["decisions"][-1]["hash"] if o["decisions"] else None
        d = {
            "seq": len(o["decisions"]),
            "kind": kind,
            "at": self.clock(),
            "actor": actor,
            "session_token_id": session_token_id,
            "reason": reason,
            "detail": detail,
            "prev": prev,
        }
        d["hash"] = self._decision_hash(o, d)
        o["decisions"].append(d)
        self.audit.append("order_decision",
                          {"order_id": o["id"], "seq": d["seq"],
                           "kind": kind, "actor": actor, "reason": reason,
                           "detail": detail, "decision_hash": d["hash"],
                           "prev": prev,
                           "payload_digest": o["payload_digest"]})
        return d

    @staticmethod
    def _decision_hash(o: dict, d: dict) -> str:
        body = {
            "t": "kc-order-decision-v1",
            "order_id": o["id"],
            "op": o["op"],
            "payload_digest": o["payload_digest"],
            "deadline": o["deadline"],
            "requester": o["requester"],
            "seq": d["seq"], "kind": d["kind"], "at": d["at"],
            "actor": d["actor"], "session_token_id": d["session_token_id"],
            "reason": d["reason"], "detail": d["detail"], "prev": d["prev"],
        }
        return crypto.digest_hex(body)

    def _target_key(self, op: str, p: dict) -> str | None:
        if op in (OP_FLOW_ABORT, OP_PUBLISH, OP_PURGE):
            return f"{op}:{p.get('ceremony_id')}"
        if op == OP_POLICY_REVISE:
            return f"{OP_POLICY_REVISE}:{p.get('new_policy_id')}"
        return None

    def _get(self, order_id: str) -> dict:
        o = self.state["orders"].get(order_id)
        if o is None:
            raise NotFound(f"unknown order {order_id}")
        return o

    # ======================================================================
    # views
    # ======================================================================
    def action_view(self, session: dict | None) -> dict:
        if session is None:
            return {"can_request": [], "can_approve": [],
                    "scopes": []}
        duties = set(self._effective_duties(session))
        can_request = [op for op, (reqd, _) in ACTION_CATALOGUE.items()
                       if reqd in duties]
        can_approve = [op for op, (_, apd) in ACTION_CATALOGUE.items()
                       if apd in duties]
        return {"can_request": can_request, "can_approve": can_approve,
                "scopes": sorted(scopes_for(duties))}

    @staticmethod
    def public_session(s: dict) -> dict:
        return {k: v for k, v in s.items()}

    @staticmethod
    def public_order(o: dict) -> dict:
        return {
            "id": o["id"], "op": o["op"], "payload": o["payload"],
            "payload_digest": o["payload_digest"], "deadline": o["deadline"],
            "status": o["status"], "requester": o["requester"],
            "approver_duty": o["approver_duty"], "approver": o.get("approver"),
            "decisions": o["decisions"], "created_at": o["created_at"],
            "decided_at": o.get("decided_at"), "result": o.get("result"),
            "close_reason": o.get("close_reason"),
            "execution_error": o.get("execution_error"),
        }

    def list_orders(self) -> list[dict]:
        return [self.public_order(o)
                for o in sorted(self.state["orders"].values(),
                                key=lambda x: x["created_at"])]

    def list_sessions(self) -> list[dict]:
        return [self.public_session(s)
                for s in sorted(self.state["sessions"].values(),
                                key=lambda x: x["created_at"])]
