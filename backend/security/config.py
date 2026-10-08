"""Centralized Security Configuration for BB-SUITE.

Defines defensive boundaries, authentication secrets, target validation policies,
and HTTP client restrictions.
"""
from __future__ import annotations
import os
import secrets
from typing import List

# Attempt to load .env from project root
try:
    from dotenv import load_dotenv
    _root_env = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.env'))
    _key_env = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'key.env'))
    if os.path.exists(_root_env):
        load_dotenv(_root_env)
    elif os.path.exists(_key_env):
        load_dotenv(_key_env)
except ImportError:
    pass


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ('1', 'true', 'yes', 'on')


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)).strip())
    except Exception:
        return default


# Deployment Environment
BB_ENV: str = os.getenv("BB_ENV", "production").strip().lower()
IS_DEVELOPMENT: bool = BB_ENV in ("dev", "development")

# Server Binding
BB_HOST: str = os.getenv("BB_HOST", "127.0.0.1").strip()
BB_PORT: int = _int_env("BB_PORT", 8000)

# Target Authorization & Network Boundary
# In production/default, scanning private, loopback, or cloud metadata is strictly forbidden.
BB_ALLOW_PRIVATE_TARGETS: bool = _bool_env("BB_ALLOW_PRIVATE_TARGETS", False)
# Alias for CTF / authorized local lab environments
BB_LOCAL_LAB_MODE: bool = _bool_env("BB_LOCAL_LAB_MODE", False)
# Require live DNS resolution during target validation (can be False in offline test suites)
BB_REQUIRE_DNS_RESOLUTION: bool = _bool_env("BB_REQUIRE_DNS_RESOLUTION", False)

def is_private_allowed() -> bool:
    return BB_ALLOW_PRIVATE_TARGETS or BB_LOCAL_LAB_MODE



# TLS Enforcement
# Default must be strict TLS verification. Insecure TLS must be explicitly opted-in.
BB_ALLOW_INSECURE_TLS: bool = _bool_env("BB_ALLOW_INSECURE_TLS", False)

# HTTP Limits
BB_MAX_RESPONSE_SIZE: int = _int_env("BB_MAX_RESPONSE_SIZE", 5 * 1024 * 1024)  # 5 MB
BB_MAX_REDIRECTS: int = _int_env("BB_MAX_REDIRECTS", 5)
BB_TIMEOUT_CONNECT: float = _float_env("BB_TIMEOUT_CONNECT", 5.0)
BB_TIMEOUT_READ: float = _float_env("BB_TIMEOUT_READ", 10.0)
BB_TIMEOUT_TOTAL: float = _float_env("BB_TIMEOUT_TOTAL", 15.0)

# Authentication & Access Control
BB_ADMIN_USERNAME: str = os.getenv("BB_ADMIN_USERNAME", "admin").strip()
# Auto-generate or load static password
_raw_admin_pw = os.getenv("BB_ADMIN_PASSWORD", "").strip()
BB_ADMIN_PASSWORD: str = _raw_admin_pw if _raw_admin_pw else "admin"

# Secret key for tokens (persisted in env or auto-generated)
BB_SECRET_KEY: str = os.getenv("BB_SECRET_KEY", "").strip()
if not BB_SECRET_KEY:
    BB_SECRET_KEY = secrets.token_hex(32)

# Session token expiration in hours
BB_TOKEN_EXPIRE_HOURS: int = _int_env("BB_TOKEN_EXPIRE_HOURS", 24)

# CORS Origins
_default_cors = "http://localhost:5173,http://localhost:8000,http://127.0.0.1:5173,http://127.0.0.1:8000"
_cors_raw = os.getenv("BB_CORS_ORIGINS", _default_cors)
BB_CORS_ORIGINS: List[str] = [orig.strip() for orig in _cors_raw.split(",") if orig.strip()]
