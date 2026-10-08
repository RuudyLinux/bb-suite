from __future__ import annotations
import base64
import json
import hashlib
import hmac
from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel
from tools.utils import f, ok, err

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
    token: str


def b64decode_pad(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)


def try_hmac_crack(header_b64: str, payload_b64: str, signature: str, alg: str) -> str | None:
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
    return None


@router.post("/jwt_analyzer")
async def jwt_analyzer(req: JwtReq):
    token = req.token.strip()
    # Strip "Bearer " prefix if present
    if token.lower().startswith('bearer '):
        token = token[7:].strip()

    parts = token.split('.')
    if len(parts) != 3:
        return err("Invalid JWT format — expected 3 parts separated by '.'")

    header_b64, payload_b64, sig_b64 = parts
    findings = []
    records  = []

    # Decode header
    try:
        header = json.loads(b64decode_pad(header_b64))
    except Exception as e:
        return err(f"Cannot decode JWT header: {e}")

    # Decode payload
    try:
        payload = json.loads(b64decode_pad(payload_b64))
    except Exception as e:
        return err(f"Cannot decode JWT payload: {e}")

    alg = header.get('alg', '').upper()
    typ = header.get('typ', 'JWT')
    kid = header.get('kid', '')

    # === Algorithm checks ===
    if alg == 'NONE' or alg == '':
        findings.append(f('critical', 'JWT Algorithm is "none"',
                           'No signature verification — token can be forged by anyone',
                           'Reject tokens with alg=none; always verify signature server-side'))
    elif alg in ['HS256', 'HS384', 'HS512']:
        findings.append(f('info', f'HMAC Algorithm: {alg}',
                           'Symmetric key — both sign and verify use same secret',
                           'Ensure secret is long (256+ bits) and randomly generated'))
        # Try to crack
        cracked_key = try_hmac_crack(header_b64, payload_b64, sig_b64, alg)
        if cracked_key is not None:
            key_disp = repr(cracked_key) if cracked_key else '(empty string)'
            findings.append(f('critical', f'JWT Secret Cracked: {key_disp}',
                               f'Weak HMAC secret found — can forge any JWT',
                               'Generate a strong random 256-bit secret immediately'))
        else:
            findings.append(f('pass', 'JWT Secret Not in Common Wordlist',
                               f'Checked {len(WEAK_KEYS)} common secrets — none matched', ''))
    elif alg in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
        findings.append(f('pass', f'Asymmetric Algorithm: {alg}',
                           'Public/private key pair — more secure if keys are managed properly', ''))
        # Algorithm confusion attack hint
        findings.append(f('medium', 'Algorithm Confusion Attack (Manual Test)',
                           f'Try changing alg from {alg} to HS256 and signing with the public key',
                           'Server must explicitly enforce expected algorithm type'))
    else:
        findings.append(f('medium', f'Unknown Algorithm: {alg}',
                           'Non-standard algorithm — may not be properly validated', ''))

    # kid injection check
    if kid:
        findings.append(f('high', f'JWT has "kid" (Key ID): {kid}',
                           'Key ID may be injectable into SQL/path traversal if used in DB lookup',
                           'Sanitize kid parameter; use a fixed key ID whitelist'))
        records.append({'Field': 'kid', 'Value': kid, 'Risk': 'Potential SQL/path injection'})

    # === Claim checks ===
    now = datetime.now(timezone.utc).timestamp()

    # Expiry
    exp = payload.get('exp')
    if exp is None:
        findings.append(f('high', 'JWT Has No Expiry (exp claim missing)',
                           'Token never expires — stolen token valid forever',
                           'Always include exp claim; use short expiry (15min–1hr)'))
    else:
        exp_dt  = datetime.fromtimestamp(exp, timezone.utc)
        exp_sec = exp - now
        if exp_sec < 0:
            findings.append(f('medium', f'JWT Already Expired',
                               f'Expired at {exp_dt.isoformat()} ({abs(int(exp_sec//3600))} hrs ago)',
                               'Server should reject expired tokens'))
        elif exp_sec > 86400 * 30:
            findings.append(f('medium', f'JWT Expiry Too Long ({int(exp_sec//3600)} hrs)',
                               'Long-lived tokens increase breach window',
                               'Use short expiry + refresh tokens'))
        else:
            findings.append(f('pass', f'JWT Expiry OK — {int(exp_sec//3600)}h remaining',
                               exp_dt.isoformat(), ''))
        records.append({'Field': 'exp', 'Value': exp_dt.isoformat(), 'Risk': 'OK' if exp_sec > 0 else 'EXPIRED'})

    # Not Before
    nbf = payload.get('nbf')
    if nbf and nbf > now:
        findings.append(f('low', 'JWT not yet valid (nbf in future)',
                           f"Valid from: {datetime.fromtimestamp(nbf, timezone.utc).isoformat()}", ''))

    # Issued At
    iat = payload.get('iat')
    if iat:
        iat_dt = datetime.fromtimestamp(iat, timezone.utc)
        records.append({'Field': 'iat', 'Value': iat_dt.isoformat(), 'Risk': 'Info'})

    # Sensitive data in payload
    SENSITIVE_FIELDS = ['password', 'passwd', 'secret', 'credit_card', 'ssn', 'dob',
                        'pin', 'cvv', 'private_key', 'api_key', 'token']
    for key in payload:
        if any(s in key.lower() for s in SENSITIVE_FIELDS):
            findings.append(f('high', f'Sensitive Field in JWT Payload: {key}',
                               'Sensitive data in JWT payload is visible to anyone with the token',
                               'Never store sensitive data in JWT payload — it is base64 encoded, not encrypted'))

    # Build records
    for k, v in header.items():
        records.append({'Field': f'header.{k}', 'Value': str(v), 'Risk': '—'})
    for k, v in payload.items():
        if k not in ('exp', 'iat', 'nbf', 'kid'):
            records.append({'Field': f'payload.{k}', 'Value': str(v)[:100], 'Risk': '—'})

    return ok({
        'summary': {
            'Algorithm':  alg,
            'Type':       typ,
            'Subject':    payload.get('sub', '—'),
            'Issuer':     payload.get('iss', '—'),
            'Audience':   str(payload.get('aud', '—')),
            'Has Expiry': 'YES' if exp else 'NO',
        },
        'findings':       findings,
        'records':        records,
        'record_columns': ['Field', 'Value', 'Risk'],
        'raw':            json.dumps({'header': header, 'payload': payload}, indent=2),
    })
