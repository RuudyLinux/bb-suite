"""FastAPI Router for BB-SUITE Authentication Endpoints."""
from __future__ import annotations
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from backend.models import LoginReq
from backend.security.auth import (
    create_access_token,
    get_current_user,
    optional_current_user,
    revoke_token,
    verify_login_credentials,
)
from backend.security.config import (
    BB_ADMIN_USERNAME,
    BB_ENV,
    BB_TOKEN_EXPIRE_HOURS,
    is_private_allowed,
)
from backend.security.logger import log_security_event

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/login")
async def login(req: LoginReq, request: Request):
    """Authenticate administrator credentials and return an access token."""
    client_ip = request.client.host if request.client else "unknown"
    if not verify_login_credentials(req.username, req.password):
        log_security_event(
            event_type="AUTH_LOGIN_FAILED",
            target="local_auth",
            user=req.username,
            details={"client_ip": client_ip},
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    token, expires_at = create_access_token(req.username)
    log_security_event(
        event_type="AUTH_LOGIN_SUCCESS",
        target="local_auth",
        user=req.username,
        details={"client_ip": client_ip},
        level="info",
    )

    return {
        "success": True,
        "token": token,
        "username": req.username,
        "expires_at": expires_at,
        "token_type": "bearer",
    }


@auth_router.get("/status")
async def auth_status(user: Optional[Dict[str, Any]] = Depends(optional_current_user)):
    """Check current session status and environment policy."""
    return {
        "success": True,
        "authenticated": user is not None,
        "user": user.get("sub") if user else None,
        "environment": BB_ENV,
        "allow_private_targets": is_private_allowed(),
    }


@auth_router.post("/logout")
async def logout(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Revoke the current access token."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if token:
        revoke_token(token)
    log_security_event(
        event_type="AUTH_LOGOUT",
        target="local_auth",
        user=user.get("sub", "admin"),
        level="info",
    )
    return {"success": True, "message": "Logged out successfully."}
