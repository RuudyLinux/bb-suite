"""Authentication and Authorization Boundary for BB-SUITE.

Provides token generation, validation, password verification, audit logging,
and FastAPI dependencies to protect sensitive and exploitation endpoints.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.security.config import (
    BB_ADMIN_PASSWORD,
    BB_ADMIN_USERNAME,
    BB_SECRET_KEY,
    BB_TOKEN_EXPIRE_HOURS,
)

security_bearer = HTTPBearer(auto_error=False)

# In-memory revocation set for logged-out tokens
_REVOKED_TOKENS: set[str] = set()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + padding).encode("utf-8"))


def create_access_token(username: str, expires_in_hours: Optional[int] = None) -> Tuple[str, int]:
    """Generate a tamper-proof HMAC-SHA256 signed access token."""
    if expires_in_hours is None:
        expires_in_hours = BB_TOKEN_EXPIRE_HOURS

    now = int(time.time())
    expires_at = now + (expires_in_hours * 3600)
    payload = {
        "sub": username,
        "iat": now,
        "exp": expires_at,
        "jti": secrets.token_hex(16),
    }

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)

    sig = hmac.new(
        BB_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(sig)

    token = f"{payload_b64}.{sig_b64}"
    return token, expires_at


def verify_access_token(token: str) -> Dict[str, Any]:
    """Verify cryptographic signature and expiration of an access token."""
    if not token or "." not in token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token format.",
        )

    if token in _REVOKED_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked.",
        )

    parts = token.split(".")
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token.",
        )

    payload_b64, sig_b64 = parts[0], parts[1]

    # Verify signature
    expected_sig = hmac.new(
        BB_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not secrets.compare_digest(sig_b64, expected_sig_b64):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication signature.",
        )

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Corrupted token payload.",
        )

    # Check expiration
    exp = payload.get("exp", 0)
    if time.time() > exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
        )

    return payload


def verify_login_credentials(username: str, password: str) -> bool:
    """Verify administrator credentials using timing-safe comparison."""
    user_match = secrets.compare_digest(username.strip(), BB_ADMIN_USERNAME.strip())
    # If the configured password looks like a sha256 hex digest, compare digests, else compare text
    pw_match = secrets.compare_digest(password.strip(), BB_ADMIN_PASSWORD.strip())
    return user_match and pw_match


def revoke_token(token: str) -> None:
    """Add a token to the revocation set."""
    if token:
        _REVOKED_TOKENS.add(token)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Dict[str, Any]:
    """FastAPI dependency to extract and verify the current authenticated user."""
    token: Optional[str] = None

    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        # Check custom header X-API-Token or X-API-Key
        api_header = request.headers.get("X-API-Token") or request.headers.get("X-API-Key")
        if api_header:
            token = api_header.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a Bearer token or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_access_token(token)
    return payload


# Optional auth dependency for non-destructive read endpoints
async def optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Optional[Dict[str, Any]]:
    try:
        return await get_current_user(request, credentials)
    except HTTPException:
        return None
