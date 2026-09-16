"""Agent identity — signed credentials and commerce mandate verification.

Replaces the trust-me integer ``permission_level`` with a verifiable
credential: a compact HS256 JWT issued per agent, per brand. When an agent
stack presents a *mandate* (Visa Intelligent Commerce / Mastercard Agent
Suite / AP2 style), the pluggable verifier registry validates it; brands
that don't use mandates fall back to the internal permission model.

Every evaluation records *provenance* (which credential, which verifier,
which version) so the audit trail answers "who let this agent act?".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from opsonara.core.exceptions import NotFoundError

# ---------------------------------------------------------------------------
# signed agent credentials (compact HS256 JWT)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class AgentCredentialError(NotFoundError):
    """Raised when a presented credential is invalid, expired, or untrusted."""


# Agent lifecycle states (spec §3): ACTIVE is implicit (not tracked);
# PAUSED/QUARANTINED are recoverable, REVOKED/DECOMMISSIONED are terminal.
AGENT_ACTIVE = "active"
AGENT_PAUSED = "paused"
AGENT_QUARANTINED = "quarantined"
AGENT_REVOKED = "revoked"


class AgentStateError(AgentCredentialError):
    """Agent exists but its lifecycle state forbids this action."""


@dataclass
class AgentCredential:
    """A signed per-agent, per-brand credential."""

    agent_id: str
    brand_id: str
    permission_level: int
    framework: str = "opsonara"
    framework_version: str = "1.0"
    issued_at: int = 0
    expires_at: int = 0
    lifecycle_state: str = AGENT_ACTIVE
    """Set by ``CredentialAuthority.verify`` — not part of the signed claims."""

    def claims(self) -> dict[str, Any]:
        return {
            "sub": self.agent_id,
            "brand": self.brand_id,
            "level": self.permission_level,
            "fw": self.framework,
            "fwv": self.framework_version,
            "iat": self.issued_at,
            "exp": self.expires_at,
        }


class CredentialAuthority:
    """Issues and verifies HS256 agent credentials.

    Also owns the agent lifecycle (spec §3, §28–§29):

    * ``revoke(agent_id)`` — terminal; every verify raises.
    * ``pause`` / ``resume`` — all actions refused while paused.
    * ``quarantine`` — compromise containment: the agent may keep *reading*
      (evaluation continues) but every sensitive action is forced to human
      review and the credential is flagged in the audit provenance.
    * ``kill_switch()`` — one call pauses *every* registered agent (the
      dashboard's big red button); ``resume_all()`` undoes it.
    """

    def __init__(self, signing_key: str | None = None) -> None:
        self._key = signing_key or secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self._revoked: set[str] = set()
        self._states: dict[str, str] = {}  # agent_id -> lifecycle state
        self._known: set[str] = set()  # every agent we ever issued for
        self._pre_kill_active: set[str] | None = None

    def issue(
        self,
        agent_id: str,
        brand_id: str,
        permission_level: int,
        *,
        ttl_seconds: int = 3600,
        framework: str = "opsonara",
        framework_version: str = "1.0",
    ) -> tuple[str, AgentCredential]:
        now = int(time.time())
        with self._lock:
            self._known.add(agent_id)
            self._states.pop(agent_id, None)  # re-issue resets lifecycle state
        cred = AgentCredential(
            agent_id=agent_id,
            brand_id=brand_id,
            permission_level=permission_level,
            framework=framework,
            framework_version=framework_version,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        header = {"alg": "HS256", "typ": "JWT"}
        token = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(cred.claims(), separators=(",", ":")).encode())
            + "."
            + self._sign(
                _b64url(json.dumps(header, separators=(",", ":")).encode())
                + "."
                + _b64url(json.dumps(cred.claims(), separators=(",", ":")).encode())
            )
        )
        return token, cred

    def verify(self, token: str, *, brand_id: str | None = None) -> AgentCredential:
        """Verify signature, expiry and revocation; optionally pin the brand."""
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
            if json.loads(_b64url_decode(header_b64)).get("alg") != "HS256":
                raise AgentCredentialError("unsupported credential algorithm")
            expected = self._sign(f"{header_b64}.{payload_b64}")
            if not hmac.compare_digest(expected, signature_b64):
                raise AgentCredentialError("credential signature invalid")
            claims = json.loads(_b64url_decode(payload_b64))
        except AgentCredentialError:
            raise
        except Exception as exc:
            raise AgentCredentialError(f"malformed credential: {exc}") from exc

        cred = AgentCredential(
            agent_id=str(claims.get("sub", "")),
            brand_id=str(claims.get("brand", "")),
            permission_level=int(claims.get("level", 0)),
            framework=str(claims.get("fw", "opsonara")),
            framework_version=str(claims.get("fwv", "1.0")),
            issued_at=int(claims.get("iat", 0)),
            expires_at=int(claims.get("exp", 0)),
        )
        if not cred.agent_id:
            raise AgentCredentialError("credential has no subject")
        if cred.expires_at and cred.expires_at < time.time():
            raise AgentCredentialError("credential expired")
        with self._lock:
            if cred.agent_id in self._revoked:
                raise AgentCredentialError(f"credential for '{cred.agent_id}' revoked")
            state = self._states.get(cred.agent_id, AGENT_ACTIVE)
        if state == AGENT_PAUSED:
            raise AgentStateError(f"agent '{cred.agent_id}' is paused (kill switch or manual)")
        if brand_id is not None and cred.brand_id != brand_id:
            raise AgentCredentialError(
                f"credential issued for brand '{cred.brand_id}', not '{brand_id}'"
            )
        cred.lifecycle_state = state
        return cred

    def revoke(self, agent_id: str) -> None:
        with self._lock:
            self._revoked.add(agent_id)
            self._states.pop(agent_id, None)

    # -- lifecycle management (spec §3, §28–§29) ---------------------------

    def pause(self, agent_id: str) -> str:
        """Refuse all actions for this agent until resumed."""
        with self._lock:
            self._states[agent_id] = AGENT_PAUSED
            return AGENT_PAUSED

    def resume(self, agent_id: str) -> str:
        """Return a paused/quarantined agent to active."""
        with self._lock:
            self._states.pop(agent_id, None)
            return AGENT_ACTIVE

    def quarantine(self, agent_id: str) -> str:
        """Compromise containment: reads continue, sensitive actions are
        forced to human review (see ``FirewallEngine.evaluate``)."""
        with self._lock:
            self._states[agent_id] = AGENT_QUARANTINED
            return AGENT_QUARANTINED

    def kill_switch(self) -> list[str]:
        """Pause every agent ever issued. Returns the affected agent IDs.

        The dashboard's "PAUSE ALL AGENTS" button (spec §28). """
        with self._lock:
            previously_active = {
                a
                for a in self._known
                if self._states.get(a, AGENT_ACTIVE) == AGENT_ACTIVE
                and a not in self._revoked
            }
            for agent_id in previously_active:
                self._states[agent_id] = AGENT_PAUSED
            self._pre_kill_active = previously_active
            return sorted(previously_active)

    def resume_all(self) -> list[str]:
        """Undo a kill switch: re-activate exactly the agents it paused."""
        with self._lock:
            affected = self._pre_kill_active or set()
            for agent_id in affected:
                if self._states.get(agent_id) == AGENT_PAUSED:
                    self._states.pop(agent_id, None)
            self._pre_kill_active = None
            return sorted(affected)

    def state_of(self, agent_id: str) -> str:
        with self._lock:
            return self._states.get(agent_id, AGENT_ACTIVE)

    def agents(self) -> dict[str, str]:
        """Snapshot of every known agent and its lifecycle state."""
        with self._lock:
            return {
                a: self._states.get(a, AGENT_ACTIVE)
                for a in sorted(self._known | set(self._states))
            }

    def _sign(self, payload: str) -> str:
        return _b64url(hmac.new(self._key.encode(), payload.encode(), hashlib.sha256).digest())


# ---------------------------------------------------------------------------
# mandate verification (Visa IC / Mastercard Agent Suite / AP2 style)
# ---------------------------------------------------------------------------


class MandateVerifier(Protocol):
    """Pluggable verifier for signed commerce mandates."""

    def scheme(self) -> str: ...

    def verify(self, mandate: dict[str, Any], *, brand_id: str) -> dict[str, Any]: ...


@dataclass
class MandateVerdict:
    scheme: str
    valid: bool
    detail: str
    agent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"scheme": self.scheme, "valid": self.valid, "detail": self.detail,
                "agent_id": self.agent_id}


class Ap2MandateVerifier:
    """Verifies AP2-style signed mandates (HMAC-signed authorization proofs)."""

    def __init__(self, brand_secrets: dict[str, str]) -> None:
        self._secrets = brand_secrets

    def scheme(self) -> str:
        return "ap2"

    def verify(self, mandate: dict[str, Any], *, brand_id: str) -> dict[str, Any]:
        secret = self._secrets.get(brand_id)
        if not secret:
            return {"valid": False, "detail": f"no AP2 secret registered for brand '{brand_id}'"}
        payload = mandate.get("payload")
        signature = mandate.get("signature")
        if not payload or not signature:
            return {"valid": False, "detail": "mandate missing payload/signature"}
        if not isinstance(payload, dict):
            return {"valid": False, "detail": "mandate payload must be a JSON object"}
        expected = _b64url(
            hmac.new(secret.encode(), json.dumps(payload, sort_keys=True).encode(),
                     hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, str(signature)):
            return {"valid": False, "detail": "mandate signature invalid"}
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, (int, float)) and expires_at < time.time():
            return {"valid": False, "detail": "mandate expired"}
        agent_id = str(payload.get("agent_id", ""))
        return {"valid": True, "detail": "AP2 mandate verified", "agent_id": agent_id}


class MandateRegistry:
    """Registry of scheme verifiers; empty registry = internal model only."""

    def __init__(self) -> None:
        self._verifiers: dict[str, MandateVerifier] = {}

    def register(self, verifier: MandateVerifier) -> None:
        self._verifiers[verifier.scheme()] = verifier

    def schemes(self) -> list[str]:
        return sorted(self._verifiers)

    def verify(self, mandate: Any, *, brand_id: str) -> MandateVerdict:
        """Verify a presented mandate. Never raises: malformed input —
        wrong type, unserializable payloads, verifier bugs — becomes an
        ``invalid`` verdict (the firewall then treats it as unverified),
        never an HTTP 500."""
        if not isinstance(mandate, dict):
            return MandateVerdict(
                scheme="none",
                valid=False,
                detail="mandate must be a JSON object",
            )
        scheme = str(mandate.get("scheme", ""))
        verifier = self._verifiers.get(scheme)
        if verifier is None:
            return MandateVerdict(
                scheme=scheme or "none",
                valid=False,
                detail=f"no verifier registered for mandate scheme '{scheme}'",
            )
        try:
            result = verifier.verify(mandate, brand_id=brand_id)
            valid = bool(result.get("valid"))
            detail = str(result.get("detail", ""))
            agent_id = result.get("agent_id")
        except Exception as exc:  # noqa: BLE001 — a broken verifier is a verdict, not a crash
            return MandateVerdict(
                scheme=scheme,
                valid=False,
                detail=f"mandate verification error: {exc}",
            )
        return MandateVerdict(scheme=scheme, valid=valid, detail=detail, agent_id=agent_id)


def provenance_from_credential(cred: AgentCredential | None) -> dict[str, Any]:
    """Audit-log provenance block for a verified credential."""
    if cred is None:
        return {"credential": "unverified", "framework": "unknown", "framework_version": "unknown"}
    return {
        "credential": "verified",
        "agent_id": cred.agent_id,
        "brand_id": cred.brand_id,
        "permission_level": cred.permission_level,
        "framework": cred.framework,
        "framework_version": cred.framework_version,
        "expires_at": cred.expires_at,
    }


__all__ = [
    "AGENT_ACTIVE",
    "AGENT_PAUSED",
    "AGENT_QUARANTINED",
    "AGENT_REVOKED",
    "AgentCredential",
    "AgentCredentialError",
    "AgentStateError",
    "Ap2MandateVerifier",
    "CredentialAuthority",
    "MandateRegistry",
    "MandateVerifier",
    "MandateVerdict",
    "provenance_from_credential",
]
