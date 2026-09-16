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
    """Issues and verifies HS256 agent credentials."""

    def __init__(self, signing_key: str | None = None) -> None:
        self._key = signing_key or secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self._revoked: set[str] = set()

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
        if brand_id is not None and cred.brand_id != brand_id:
            raise AgentCredentialError(
                f"credential issued for brand '{cred.brand_id}', not '{brand_id}'"
            )
        return cred

    def revoke(self, agent_id: str) -> None:
        with self._lock:
            self._revoked.add(agent_id)

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
        expected = _b64url(
            hmac.new(secret.encode(), json.dumps(payload, sort_keys=True).encode(),
                     hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, str(signature)):
            return {"valid": False, "detail": "mandate signature invalid"}
        agent_id = str(payload.get("agent_id", "")) if isinstance(payload, dict) else ""
        return {"valid": True, "detail": "AP2 mandate verified", "agent_id": agent_id}


class MandateRegistry:
    """Registry of scheme verifiers; empty registry = internal model only."""

    def __init__(self) -> None:
        self._verifiers: dict[str, MandateVerifier] = {}

    def register(self, verifier: MandateVerifier) -> None:
        self._verifiers[verifier.scheme()] = verifier

    def schemes(self) -> list[str]:
        return sorted(self._verifiers)

    def verify(self, mandate: dict[str, Any], *, brand_id: str) -> MandateVerdict:
        scheme = str(mandate.get("scheme", ""))
        verifier = self._verifiers.get(scheme)
        if verifier is None:
            return MandateVerdict(
                scheme=scheme or "none",
                valid=False,
                detail=f"no verifier registered for mandate scheme '{scheme}'",
            )
        result = verifier.verify(mandate, brand_id=brand_id)
        return MandateVerdict(
            scheme=scheme,
            valid=bool(result.get("valid")),
            detail=str(result.get("detail", "")),
            agent_id=result.get("agent_id"),
        )


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
    "AgentCredential",
    "AgentCredentialError",
    "Ap2MandateVerifier",
    "CredentialAuthority",
    "MandateRegistry",
    "MandateVerifier",
    "MandateVerdict",
    "provenance_from_credential",
]
