"""Authoritative Pydantic Request and Response Models for BB-SUITE.

Enforces strict input validation, length bounds, parameter limits,
and structural constraints across all security tool endpoints.
"""
from __future__ import annotations
import re
from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator


def _clean_str(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    # Reject control characters
    if any(c in s for c in ("\r", "\n", "\x00")):
        s = re.sub(r'[\r\n\x00]+', '', s).strip()
    return s


class LoginReq(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)

    @field_validator("username", "password")
    @classmethod
    def sanitize(cls, v: str) -> str:
        return _clean_str(v)


class TargetReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048, description="Target URL, domain, or IP")

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        res = _clean_str(v)
        if not res:
            raise ValueError("Target must not be empty.")
        return res


class PageDiscoverReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    depth: int = Field(2, ge=1, le=5)
    max_pages: int = Field(150, ge=1, le=500)
    wordlist: str = Field("medium", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class PortScanReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    ports: str = Field("common", max_length=1024)

    @field_validator("target", "ports")
    @classmethod
    def clean_fields(cls, v: str) -> str:
        return _clean_str(v)


class TlsReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    port: int = Field(443, ge=1, le=65535)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class SubdomainReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    wordlist: str = Field("medium", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class WordlistReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    wordlist: str = Field("medium", max_length=64)
    filter: str = Field("found", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class CorsReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    origin: str = Field("", max_length=512)

    @field_validator("target", "origin")
    @classmethod
    def clean_fields(cls, v: str) -> str:
        return _clean_str(v)


class CloudReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class SqliReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    type: str = Field("all", max_length=64)
    db: str = Field("all", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class BruteReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    username_field: str = Field("username", max_length=128)
    password_field: str = Field("password", max_length=128)
    username: str = Field("admin", max_length=128)
    success_indicator: str = Field("", max_length=256)
    passwords: str = Field("", max_length=100000)
    credentials: str = Field("", max_length=100000)
    concurrency: int = Field(5, ge=1, le=20)
    payload_type: str = Field("form", max_length=64)
    wordlist_size: str = Field("medium", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class PasswordCrackReq(BaseModel):
    mode: str = Field("hash_crack", max_length=64)
    hashes: str = Field("", max_length=50000)
    hash_type: str = Field("auto", max_length=64)
    attack_type: str = Field("all", max_length=64)
    custom_wordlist: str = Field("", max_length=100000)
    salt: str = Field("", max_length=256)
    mask: str = Field("?d?d?d?d", max_length=64)
    target_info: str = Field("", max_length=1024)
    passwords: str = Field("", max_length=50000)


class StuffingReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    username_field: str = Field("email", max_length=128)
    password_field: str = Field("password", max_length=128)
    success_indicator: str = Field("", max_length=256)
    credentials: str = Field(..., max_length=50000)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class AuthFlawsReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    username_field: str = Field("username", max_length=128)
    password_field: str = Field("password", max_length=128)
    username: str = Field("admin", max_length=128)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class ZapReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    scan_type: str = Field("active", max_length=64)
    api_key: str = Field("", max_length=256)
    zap_host: str = Field("http://localhost:8080", max_length=512)
    action: str = Field("scan", max_length=64)

    @field_validator("target", "zap_host")
    @classmethod
    def clean_urls(cls, v: str) -> str:
        return _clean_str(v)


class RateLimitReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    requests: int = Field(50, ge=1, le=300)
    concurrency: int = Field(5, ge=1, le=20)
    custom_header: str = Field("", max_length=256)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class VulnMapReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    max_pages: int = Field(40, ge=1, le=100)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class SsrfReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    param: str = Field("", max_length=128)
    mode: str = Field("all", max_length=64)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class SstiReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    param: str = Field("", max_length=128)
    method: str = Field("GET", max_length=16)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class GraphqlReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    endpoint: str = Field("", max_length=512)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class ProtoReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    method: str = Field("ALL", max_length=16)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class PocReq(BaseModel):
    vuln_type: str = Field("xss", max_length=64)
    target: str = Field("https://example.com/search", min_length=1, max_length=2048)
    parameter: str = Field("q", max_length=128)
    custom_payload: str = Field("", max_length=2048)
    http_method: str = Field("GET", max_length=16)

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        return _clean_str(v)


class AiAnalysisReq(BaseModel):
    target: str = Field("", max_length=2048)
    findings: List[Any] = Field(default_factory=list)
    engine: str = Field("builtin", max_length=64)
    local_url: str = Field("", max_length=512)
    model: str = Field("deepseek-r1", max_length=128)
