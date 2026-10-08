"""JWT Analyzer — Cryptographic Assessment & Structural Inspector.

Distinguishes between theoretical token properties and verifiable vulnerabilities:
- Confirmed: Cryptographically verified weak HMAC secret brute-forced offline, or missing claims.
- Likely: Alg=none header property present in active token.
- Possible: Theoretical algorithm confusion attack surface or long expiration windows.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.logger import redact_secrets
from backend.tools.utils import err, ok

router = APIRouter(tags=["scanning"])

WEAK_KEYS = [
    '', 'secret', 'password', 'key', 'jwt', 'jwtkey', 'jwt_secret',
    'your-256-bit-secret', 'your-secret', 'changeme', 'mysecret',
    'supersecret', 'topsecret', 'verysecret', 'secretkey',
    'admin', 'root', '123456', 'qwerty', 'default', 'test',
    'development', 'production', 'staging', '1234567890',
    'HS256', 'RS256', 'none', 'null', '0', 'keyboardcat',
    'shhhhh', 'unsafe', 'secret123', 'pass', 'hello',
]


class JwtReq(BaseModel):
    token: str = Field(..., min_length=1, max_length=10000)


def b64decode_pad(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)


def try_hmac_crack(header_b64: str, payload_b64: str, signature: str, alg: str) -> Optional[str]:
    try:
        sig_bytes = b64decode_pad(signature)
        msg = f"{header_b64}.{payload_b64}".encode()
        hash_fn = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for key in WEAK_KEYS:
            expected = hmac.new(key.encode(), msg, hash_fn).digest()
            if hmac.compare_digest(expected, sig_bytes):
                return key
    except Exception:
        pass
    return None


@router.post("/jwt_analyzer")
async def jwt_analyzer(req: JwtReq):
    token = req.token.strip()
    if token.lower().startswith('bearer '):
        token = token[7:].strip()

    parts = token.split('.')
    if len(parts) != 3:
        return err("Invalid JWT structure — expected 3 dot-separated parts (header.payload.signature).")

    header_b64, payload_b64, sig_b64 = parts
    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # Decode header
    try:
        header = json.loads(b64decode_pad(header_b64).decode('utf-8', errors='replace'))
    except Exception as e:
        return err(f"Cannot decode JWT header: {e}")

    # Decode payload
    try:
        payload = json.loads(b64decode_pad(payload_b64).decode('utf-8', errors='replace'))
    except Exception as e:
        return err(f"Cannot decode JWT payload: {e}")

    alg = str(header.get('alg', '')).upper()
    kid = str(header.get('kid', ''))

    # 1. Algorithm Analysis
    if alg == 'NONE' or alg == '':
        findings.append(create_finding(
            title="Token Header Specifies alg='none'",
            severity="high",
            confidence=Confidence.LIKELY.value,
            detail="The inspected JWT header explicitly sets alg='none'. Verify whether the target server actually accepts unsigned tokens or rejects them.",
            recommendation="Configure JWT parser libraries to strictly enforce expected algorithms (e.g. HS256/RS256) and reject unsigned alg='none' tokens.",
            evidence=f"Header alg: {alg}",
        ))
        records.append({"Component": "Header", "Property": "Algorithm", "Value": "none", "Status": "Unsigned / Weak"})
    elif alg in ['HS256', 'HS384', 'HS512']:
        # Attempt offline HMAC crack
        cracked_key = try_hmac_crack(header_b64, payload_b64, sig_b64, alg)
        if cracked_key is not None:
            findings.append(create_finding(
                title=f"JWT HMAC Secret Brute-Forced (Confirmed): '{cracked_key or '<empty>'}'",
                severity="critical",
                confidence=Confidence.CONFIRMED.value,
                detail=f"The HMAC signing secret was cracked using common dictionary words. The server's JWT secret is trivial to forge.",
                recommendation="Immediately rotate the signing secret to a cryptographically random 256-bit+ value.",
                evidence=f"Cracked Secret: {cracked_key}",
            ))
            records.append({"Component": "Signature", "Property": "HMAC Secret", "Value": cracked_key, "Status": "💀 CRACKED"})
        else:
            findings.append(create_finding(
                title=f"HMAC Symmetric Algorithm ({alg})",
                severity="info",
                confidence=Confidence.NOT_DETECTED.value,
                detail=f"Token uses {alg} symmetric signing. Secret was not present in the quick top-dictionary wordlist.",
                recommendation="Ensure the HMAC secret has high entropy (>= 32 random bytes).",
            ))
            records.append({"Component": "Signature", "Property": "HMAC Secret", "Value": alg, "Status": "Passed Quick Crack"})
    elif alg in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
        findings.append(create_finding(
            title=f"Asymmetric Algorithm ({alg})",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail=f"Token uses asymmetric {alg} signing with public/private key pairs.",
            recommendation="Ensure private keys remain securely stored in HSM or key vaults.",
        ))
        records.append({"Component": "Header", "Property": "Algorithm", "Value": alg, "Status": "Asymmetric"})

    # 2. Key ID (kid) Analysis
    if kid:
        findings.append(create_finding(
            title="JWT Contains 'kid' (Key ID) Header",
            severity="low",
            confidence=Confidence.POSSIBLE.value,
            detail=f"Token contains kid='{kid}'. If the server looks up keys dynamically in a database or filesystem without validation, this may pose an injection surface.",
            recommendation="Sanitize and whitelist kid parameters before key lookup.",
            evidence=f"kid value: {kid}",
        ))
        records.append({"Component": "Header", "Property": "Key ID (kid)", "Value": kid, "Status": "Exposed"})

    # 3. Claims & Expiration Analysis
    now_ts = datetime.now(timezone.utc).timestamp()
    exp = payload.get('exp')
    if exp is None:
        findings.append(create_finding(
            title="JWT Missing Expiration ('exp' claim)",
            severity="medium",
            confidence=Confidence.CONFIRMED.value,
            detail="The JWT payload does not contain an 'exp' claim. The token cannot naturally expire.",
            recommendation="Always include an 'exp' expiration timestamp in token claims (recommended 15-60 minutes).",
            evidence="exp claim: missing",
        ))
        records.append({"Component": "Payload", "Property": "Expiration (exp)", "Value": "None", "Status": "Missing"})
    else:
        try:
            exp_val = float(exp)
            if exp_val < now_ts:
                findings.append(create_finding(
                    title="JWT Is Expired",
                    severity="info",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"The token timestamp ({datetime.fromtimestamp(exp_val, timezone.utc).isoformat()}) is in the past.",
                    recommendation="Ensure server rejects expired tokens.",
                ))
                records.append({"Component": "Payload", "Property": "Expiration (exp)", "Value": str(exp), "Status": "Expired"})
            else:
                remaining_hrs = round((exp_val - now_ts) / 3600, 1)
                records.append({"Component": "Payload", "Property": "Expiration (exp)", "Value": f"Valid for {remaining_hrs}h", "Status": "Active"})
        except Exception:
            pass

    # Sensitive data exposure in payload
    for sensitive_key in ("password", "passwd", "secret", "private_key", "credit_card", "ssn"):
        if sensitive_key in payload:
            findings.append(create_finding(
                title=f"Sensitive Field Disclosed in Token Payload: '{sensitive_key}'",
                severity="high",
                confidence=Confidence.CONFIRMED.value,
                detail=f"JWT payload contains sensitive data field '{sensitive_key}'. JWT payloads are base64 encoded and visible to anyone.",
                recommendation="Never store secrets, passwords, or PII in unencrypted JWT payloads.",
                evidence=f"Disclosed key: {sensitive_key}",
            ))

    return ok({
        "summary": {
            "Algorithm": alg,
            "Type": header.get("typ", "JWT"),
            "Claims Count": len(payload),
            "Key ID": kid or "None",
            "Has Expiration": "Yes" if exp is not None else "No",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Component", "Property", "Value", "Status"],
        "raw": json.dumps({"header": header, "payload": payload}, indent=2),
    })
