from __future__ import annotations
import math
import time
import re
import os
import hashlib
import itertools
from typing import Dict, List, Tuple, Any, Optional
from fastapi import APIRouter
from models import PasswordCrackReq
from tools.utils import f, ok, err, load_wordlist

router = APIRouter(tags=["exploitation"])

# Try importing passlib / bcrypt for advanced hashes
try:
    from passlib.hash import apr_md5_crypt, sha512_crypt, sha256_crypt, des_crypt, bcrypt as passlib_bcrypt
    HAS_PASSLIB = True
except Exception:
    HAS_PASSLIB = False

try:
    import bcrypt
    HAS_BCRYPT = True
except Exception:
    HAS_BCRYPT = False


# Common keyboard walks and sequences
KEYBOARD_WALKS = [
    "qwerty", "qwertz", "asdfgh", "zxcvbn", "123456", "12345678",
    "password", "passcode", "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
    "poiuyt", "lkjhgf", "mnbvcx", "098765", "654321", "87654321"
]

ALGO_DISPLAY_MAP = {
    "md5": ("MD5", 0),
    "ntlm": ("NTLM (Windows)", 1000),
    "sha1": ("SHA-1", 100),
    "mysql": ("MySQL 4.1+", 300),
    "sha224": ("SHA-224", 1300),
    "sha256": ("SHA-256", 1400),
    "sha384": ("SHA-384", 10800),
    "sha512": ("SHA-512", 1700),
    "sha3_224": ("SHA3-224", 17300),
    "sha3_256": ("SHA3-256", 17400),
    "sha3_384": ("SHA3-384", 17500),
    "sha3_512": ("SHA3-512", 17600),
    "bcrypt": ("Bcrypt", 3200),
    "apr1": ("Apache APR1", 1600),
    "sha512_crypt": ("SHA512-Crypt", 1800),
    "sha256_crypt": ("SHA256-Crypt", 7400),
    "des_crypt": ("Unix DES", 1500),
}


def detect_hash_candidates(h: str) -> List[Tuple[str, str, int]]:
    """
    Returns list of candidate (algo_name, display_name, hashcat_mode)
    """
    h_clean = h.strip()
    
    # Prefix-based detection
    if h_clean.startswith(("$2a$", "$2b$", "$2y$")):
        return [("bcrypt", "Bcrypt (Blowfish)", 3200)]
    if h_clean.startswith("$apr1$"):
        return [("apr1", "Apache APR1 / MD5", 1600)]
    if h_clean.startswith("$6$"):
        return [("sha512_crypt", "SHA512-Crypt (Linux)", 1800)]
    if h_clean.startswith("$5$"):
        return [("sha256_crypt", "SHA256-Crypt (Linux)", 7400)]
    if h_clean.startswith("$1$"):
        return [("apr1", "MD5-Crypt (Linux / Apache)", 500)]
    if h_clean.startswith("*") and len(h_clean) == 41 and all(c in "0123456789ABCDEFabcdef" for c in h_clean[1:]):
        return [("mysql", "MySQL 4.1+ (double SHA-1)", 300)]
    
    length = len(h_clean)
    is_hex = bool(re.match(r'^[a-fA-F0-9]+$', h_clean))

    if is_hex:
        if length == 32:
            return [("md5", "MD5", 0), ("ntlm", "NTLM (Windows)", 1000)]
        elif length == 40:
            return [("sha1", "SHA-1", 100), ("mysql", "MySQL 4.1+ (raw)", 300)]
        elif length == 56:
            return [("sha224", "SHA-224", 1300), ("sha3_224", "SHA3-224", 17300)]
        elif length == 64:
            return [("sha256", "SHA-256", 1400), ("sha3_256", "SHA3-256", 17400)]
        elif length == 96:
            return [("sha384", "SHA-384", 10800), ("sha3_384", "SHA3-384", 17500)]
        elif length == 128:
            return [("sha512", "SHA-512", 1700), ("sha3_512", "SHA3-512", 17600)]
    
    if length == 13:
        return [("des_crypt", "Unix DES (Crypt)", 1500)]

    return [("md5", "MD5", 0), ("sha1", "SHA-1", 100), ("sha256", "SHA-256", 1400), ("ntlm", "NTLM", 1000)]


def compute_fast_hash(algo: str, candidate: str, salt: str = "") -> Optional[str]:
    """Fast hashing for standard algorithms."""
    try:
        if algo == "md5":
            if salt:
                return hashlib.md5((candidate + salt).encode('utf-8')).hexdigest().lower()
            return hashlib.md5(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "sha1":
            if salt:
                return hashlib.sha1((candidate + salt).encode('utf-8')).hexdigest().lower()
            return hashlib.sha1(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "sha224":
            return hashlib.sha224((candidate + salt).encode('utf-8')).hexdigest().lower()
        elif algo == "sha256":
            if salt:
                return hashlib.sha256((candidate + salt).encode('utf-8')).hexdigest().lower()
            return hashlib.sha256(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "sha384":
            return hashlib.sha384((candidate + salt).encode('utf-8')).hexdigest().lower()
        elif algo == "sha512":
            if salt:
                return hashlib.sha512((candidate + salt).encode('utf-8')).hexdigest().lower()
            return hashlib.sha512(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "sha3_256":
            return hashlib.sha3_256(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "sha3_512":
            return hashlib.sha3_512(candidate.encode('utf-8')).hexdigest().lower()
        elif algo == "ntlm":
            # MD4 of UTF-16LE
            return hashlib.new('md4', candidate.encode('utf-16le')).hexdigest().lower()
        elif algo == "mysql":
            # * + SHA1(SHA1(pass)).upper()
            inner = hashlib.sha1(candidate.encode('utf-8')).digest()
            outer = hashlib.sha1(inner).hexdigest().upper()
            return f"*{outer}"
    except Exception:
        return None
    return None


def verify_slow_hash(algo: str, candidate: str, target_hash: str) -> bool:
    """Verifies slow or complex crypt/bcrypt hashes."""
    if not HAS_PASSLIB and not HAS_BCRYPT:
        return False
    try:
        if algo == "bcrypt":
            if HAS_BCRYPT:
                return bcrypt.checkpw(candidate.encode('utf-8'), target_hash.encode('utf-8'))
            elif HAS_PASSLIB:
                return passlib_bcrypt.verify(candidate, target_hash)
        elif algo in ("apr1", "md5_crypt") and HAS_PASSLIB:
            return apr_md5_crypt.verify(candidate, target_hash)
        elif algo == "sha512_crypt" and HAS_PASSLIB:
            return sha512_crypt.verify(candidate, target_hash)
        elif algo == "sha256_crypt" and HAS_PASSLIB:
            return sha256_crypt.verify(candidate, target_hash)
        elif algo == "des_crypt" and HAS_PASSLIB:
            return des_crypt.verify(candidate, target_hash)
    except Exception:
        return False
    return False


def generate_rule_mutations(base_words: List[str], max_limit: int = 25000) -> List[str]:
    """Generates rule-based mutations on base wordlist (leet, years, cases, symbols)."""
    mutated = []
    seen = set()

    def add(w: str):
        if w and w not in seen and len(mutated) < max_limit:
            seen.add(w)
            mutated.append(w)

    current_years = ["2023", "2024", "2025", "2026", "123", "1234", "1", "01", "99"]
    common_symbols = ["!", "@", "#", "$"]

    for word in base_words:
        if len(mutated) >= max_limit:
            break
        # Base & Case
        add(word)
        add(word.lower())
        add(word.upper())
        add(word.capitalize())
        add(word.swapcase())
        add(word[::-1])

        # Suffix years and numbers
        for y in current_years:
            add(f"{word}{y}")
            add(f"{word.capitalize()}{y}")
            for s in common_symbols:
                add(f"{word}{s}{y}")
                add(f"{word.capitalize()}{s}{y}")
                add(f"{word}{y}{s}")
                add(f"{word.capitalize()}{y}{s}")

        # Common suffixes
        for s in ["!", "@", "#", "1!", "@123", "!123", "123!"]:
            add(f"{word}{s}")
            add(f"{word.capitalize()}{s}")

        # Leet speak transformations
        leet1 = (word.replace('a', '@').replace('A', '@')
                     .replace('e', '3').replace('E', '3')
                     .replace('i', '1').replace('I', '1')
                     .replace('o', '0').replace('O', '0')
                     .replace('s', '$').replace('S', '$'))
        add(leet1)
        add(leet1 + "!")
        add(leet1 + "123")
        add(leet1 + "2025")
        add(leet1 + "2026")

        leet2 = (word.replace('a', '4')
                     .replace('e', '3')
                     .replace('t', '7')
                     .replace('l', '1'))
        add(leet2)

    return mutated


def generate_mask_candidates(mask: str, max_limit: int = 15000) -> List[str]:
    """Generates candidates from simple mask expressions (e.g. ?d?d?d?d)."""
    mask = mask.strip()
    if not mask:
        mask = "?d?d?d?d"

    # Tokenize mask
    tokens = []
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            spec = mask[i+1]
            if spec == 'd':
                tokens.append("0123456789")
            elif spec == 'l':
                tokens.append("abcdefghijklmnopqrstuvwxyz")
            elif spec == 'u':
                tokens.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            elif spec == 's':
                tokens.append("!@#$%^&*")
            else:
                tokens.append(mask[i:i+2])
            i += 2
        else:
            tokens.append(mask[i])
            i += 1

    total_combos = 1
    for t in tokens:
        total_combos *= len(t)

    candidates = []
    if total_combos <= max_limit:
        for combo in itertools.product(*tokens):
            candidates.append("".join(combo))
    else:
        for combo in itertools.islice(itertools.product(*tokens), max_limit):
            candidates.append("".join(combo))

    return candidates


def calculate_entropy_metrics(password: str) -> Dict[str, Any]:
    """Calculates password entropy, complexity, breach presence, and crack times."""
    p = password
    length = len(p)
    if length == 0:
        return {"entropy_bits": 0, "score": 0, "rating": "EMPTY", "crack_time": "Instant"}

    # Charset pool analysis
    pool_size = 0
    has_lower = bool(re.search(r'[a-z]', p))
    has_upper = bool(re.search(r'[A-Z]', p))
    has_digits = bool(re.search(r'[0-9]', p))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9\s]', p))
    has_space = ' ' in p

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digits: pool_size += 10
    if has_symbols: pool_size += 33
    if has_space: pool_size += 1

    pool_size = max(pool_size, 1)

    # Information Entropy in bits: L * log2(pool_size)
    entropy_bits = round(length * math.log2(pool_size), 1)

    # Complexity score (0 to 100)
    score = 0
    if length >= 8: score += 20
    if length >= 12: score += 20
    if length >= 16: score += 15
    if has_lower and has_upper: score += 15
    if has_digits: score += 15
    if has_symbols: score += 15

    # Penalties for patterns
    p_lower = p.lower()
    weaknesses = []
    for walk in KEYBOARD_WALKS:
        if walk in p_lower:
            score = max(0, score - 25)
            weaknesses.append(f"Contains keyboard sequence: '{walk}'")
            break

    if re.search(r'(.)\1\1', p):
        score = max(0, score - 15)
        weaknesses.append("Contains repeating characters (e.g. 'aaa')")

    if re.search(r'(19\d\d|20\d\d)', p):
        weaknesses.append("Contains calendar year (predictable ending)")

    if length < 8:
        weaknesses.append("Length is under 8 characters (critical vulnerability)")

    # Rating
    if score >= 85:
        rating = "VERY STRONG"
    elif score >= 65:
        rating = "STRONG"
    elif score >= 45:
        rating = "MODERATE"
    elif score >= 25:
        rating = "WEAK"
    else:
        rating = "VERY WEAK"

    # Crack time estimations across hardware
    total_guesses = pool_size ** length

    def format_time(seconds: float) -> str:
        if seconds < 0.001:
            return "Instant (< 1 ms)"
        elif seconds < 1:
            return f"{round(seconds * 1000)} ms"
        elif seconds < 60:
            return f"{round(seconds, 1)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        elif seconds < 31536000 * 1000:
            return f"{round(seconds / 31536000, 1)} years"
        elif seconds < 31536000 * 1_000_000:
            return f"{round(seconds / (31536000 * 1000), 1)} thousand years"
        else:
            return f"{round(seconds / (31536000 * 1_000_000), 1)} million years"

    online_throttled = 10               # 10 req/s with rate-limit
    online_unthrottled = 1000           # 1,000 req/s fast API
    cpu_speed = 100_000_000             # 100 MH/s CPU MD5
    gpu_rtx4090 = 100_000_000_000       # 100 GH/s RTX 4090 (MD5/NTLM)
    gpu_cluster = 10_000_000_000_000    # 10 TH/s Distributed GPU cluster

    crack_times = {
        "Online Web (10 guesses/sec)": format_time(total_guesses / online_throttled),
        "Online API (1k guesses/sec)": format_time(total_guesses / online_unthrottled),
        "Fast CPU (100 MH/s)": format_time(total_guesses / cpu_speed),
        "RTX 4090 GPU (100 GH/s)": format_time(total_guesses / gpu_rtx4090),
        "Cloud GPU Cluster (10 TH/s)": format_time(total_guesses / gpu_cluster),
    }

    return {
        "length": length,
        "charset_pool": pool_size,
        "entropy_bits": entropy_bits,
        "score": score,
        "rating": rating,
        "weaknesses": weaknesses,
        "crack_times": crack_times,
        "nist_compliant": length >= 12 and score >= 60,
    }


def generate_targeted_wordlist(info_str: str) -> List[str]:
    """Generates custom wordlist tailored to target profile (CUPP style)."""
    parts = [p.strip() for p in re.split(r'[,;\s]+', info_str) if p.strip()]
    if not parts:
        parts = ["admin", "target", "company"]

    base_words = set(parts)
    years = ["2023", "2024", "2025", "2026", "2027", "123", "1234", "01"]
    delims = ["", "@", "!", "#", "_", "-", "."]
    suffixes = ["admin", "root", "pass", "login", "welcome", "secure", "test", "master"]

    results = set()

    for w in base_words:
        w_lower = w.lower()
        w_cap = w.capitalize()
        w_upper = w.upper()

        results.add(w_lower)
        results.add(w_cap)
        results.add(w_upper)

        for y in years:
            for d in delims:
                results.add(f"{w_lower}{d}{y}")
                results.add(f"{w_cap}{d}{y}")
                results.add(f"{y}{d}{w_lower}")
                results.add(f"{w_cap}{d}{y}!")

        for s in suffixes:
            results.add(f"{w_lower}_{s}")
            results.add(f"{s}_{w_lower}")
            results.add(f"{w_cap}@{s}")
            results.add(f"{s}@{w_cap}")

        results.add(w_lower.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0'))
        results.add(w_cap.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0') + "!")
        results.add(w_cap.replace('a', '4').replace('e', '3') + "123")

    if len(parts) >= 2:
        for p1, p2 in itertools.permutations(parts[:4], 2):
            results.add(f"{p1}{p2}")
            results.add(f"{p1.capitalize()}{p2.capitalize()}")
            results.add(f"{p1.capitalize()}@{p2.capitalize()}")
            results.add(f"{p1}@{p2}123")
            results.add(f"{p1}_{p2}_2025")
            results.add(f"{p1}_{p2}_2026")

    return sorted(list(results))


@router.post("/password_cracker")
async def password_cracker(req: PasswordCrackReq):
    t_start = time.time()
    mode = req.mode.strip().lower()

    # ─────────────────────────────────────────────────────────────
    # MODE 1: ENTROPY AUDIT & PASSWORD STRENGTH
    # ─────────────────────────────────────────────────────────────
    if mode == "entropy_audit":
        inputs = []
        if req.passwords.strip():
            inputs = [p.strip() for p in req.passwords.strip().split("\n") if p.strip()]
        elif req.hashes.strip():
            inputs = [p.strip() for p in req.hashes.strip().split("\n") if p.strip()]
        else:
            inputs = ["Password123!", "admin", "Summer2025!", "qwerty12345", "Tr0ub4dor&3", "correct-horse-battery-staple"]

        records = []
        findings = []

        for pwd in inputs:
            metrics = calculate_entropy_metrics(pwd)
            sev = "critical" if metrics["score"] < 30 else ("high" if metrics["score"] < 50 else ("medium" if metrics["score"] < 70 else "pass"))
            recs_text = "; ".join(metrics["weaknesses"]) if metrics["weaknesses"] else "Strong entropy, no simple patterns"
            
            if sev in ("critical", "high"):
                findings.append(f(
                    sev,
                    f"Weak Password Detected: '{pwd}' ({metrics['rating']})",
                    f"Entropy: {metrics['entropy_bits']} bits, Score: {metrics['score']}/100. GPU Crack Time: {metrics['crack_times']['RTX 4090 GPU (100 GH/s)']}. Flaws: {recs_text}",
                    "Enforce >= 16 characters passphrase or password manager generated random string."
                ))

            records.append({
                "Password": pwd,
                "Length": metrics["length"],
                "Entropy (bits)": f"{metrics['entropy_bits']} b",
                "Rating": metrics["rating"],
                "Score": f"{metrics['score']}/100",
                "GPU Crack Time": metrics["crack_times"]["RTX 4090 GPU (100 GH/s)"],
                "Online Crack Time": metrics["crack_times"]["Online Web (10 guesses/sec)"],
                "NIST Compliant": "✓ YES" if metrics["nist_compliant"] else "✗ NO",
            })

        elapsed = round(time.time() - t_start, 3)
        return ok({
            "summary": {
                "Mode": "Password Strength & Entropy Audit",
                "Passwords Audited": len(records),
                "Critical/Weak Count": len([r for r in records if "WEAK" in r["Rating"]]),
                "Audit Time": f"{elapsed}s",
            },
            "findings": findings if findings else [f("pass", "Password Audit Complete", f"{len(records)} passwords analyzed")],
            "records": records,
            "record_columns": ["Password", "Length", "Entropy (bits)", "Rating", "Score", "GPU Crack Time", "Online Crack Time", "NIST Compliant"],
        })

    # ─────────────────────────────────────────────────────────────
    # MODE 2: TARGETED WORDLIST GENERATOR (CUPP)
    # ─────────────────────────────────────────────────────────────
    if mode == "wordlist_generator":
        info = req.target_info.strip() or req.hashes.strip() or "admin, corporate, 2026"
        generated = generate_targeted_wordlist(info)
        elapsed = round(time.time() - t_start, 3)

        records = [{"Index": i+1, "Candidate Password": p, "Length": len(p)} for i, p in enumerate(generated[:100])]
        
        return ok({
            "summary": {
                "Mode": "Targeted Wordlist Generator",
                "Target Profile": info,
                "Total Candidates Generated": len(generated),
                "Generation Time": f"{elapsed}s",
            },
            "findings": [
                f("info", f"Generated {len(generated)} Targeted Candidates",
                  f"Created permutations for target keywords: '{info}'. Ready for dictionary and brute-force attacks.",
                  "Pipe candidates into Hash Cracker or Online Brute Force tool.")
            ],
            "records": records,
            "record_columns": ["Index", "Candidate Password", "Length"],
            "raw": "\n".join(generated),
        })

    # ─────────────────────────────────────────────────────────────
    # MODE 3: HASH CRACKER (DEFAULT)
    # ─────────────────────────────────────────────────────────────
    hash_lines = [l.strip() for l in req.hashes.strip().split("\n") if l.strip()]
    if not hash_lines:
        hash_lines = [
            "5f4dcc3b5aa765d61d8327deb882cf99",                            # MD5 of 'password'
            "209c6174da490caeb422f3fa5a7ae634",                            # NTLM of 'admin'
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68d80",                    # SHA-1 of 'password'
            "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", # SHA-256 of 'secret123'
            "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",                    # MySQL 4.1+ of 'password'
        ]

    # Parse targets
    targets = []
    for line in hash_lines:
        user = ""
        salt = req.salt.strip()
        h_val = line

        if ":" in line:
            parts = line.split(":")
            if len(parts) == 2:
                if len(parts[1]) in (32, 40, 56, 64, 96, 128) or parts[1].startswith(("$", "*")):
                    user = parts[0]
                    h_val = parts[1]
                else:
                    h_val = parts[0]
                    salt = parts[1]
            elif len(parts) >= 3:
                user = parts[0]
                h_val = parts[1]
                salt = parts[2]

        h_clean = h_val.strip()
        detected = detect_hash_candidates(h_clean)
        algo_choice = req.hash_type.strip().lower()
        
        if algo_choice != "auto" and algo_choice:
            meta = ALGO_DISPLAY_MAP.get(algo_choice, (algo_choice.upper(), 0))
            candidate_algos = [(algo_choice, meta[0], meta[1])]
        else:
            candidate_algos = detected

        targets.append({
            "original": line,
            "user": user or "target",
            "hash": h_clean,
            "salt": salt,
            "candidate_algos": candidate_algos,
            "algo": candidate_algos[0][0],
            "algo_display": candidate_algos[0][1],
            "hashcat_mode": candidate_algos[0][2],
            "cracked": False,
            "plaintext": None,
            "time_cracked": None,
        })

    # Load candidate wordlist
    base_passwords = load_wordlist("passwords.txt")
    if not base_passwords:
        base_passwords = ["password", "123456", "admin", "root", "secret", "welcome", "pass123", "letmein", "changeme", "test", "master"]

    if req.custom_wordlist.strip():
        custom_words = [w.strip() for w in req.custom_wordlist.strip().split("\n") if w.strip()]
        base_passwords = custom_words + base_passwords

    attack = req.attack_type.strip().lower()
    candidates: List[str] = []

    if attack == "dictionary":
        candidates = base_passwords[:8000]
    elif attack == "rules":
        candidates = generate_rule_mutations(base_passwords[:300], max_limit=25000)
    elif attack == "mask":
        candidates = generate_mask_candidates(req.mask or "?d?d?d?d", max_limit=15000)
    else:  # "all"
        candidates_set = set()
        c_list = []
        def append_unique(items):
            for item in items:
                if item not in candidates_set and len(c_list) < 30000:
                    candidates_set.add(item)
                    c_list.append(item)

        append_unique(base_passwords[:2500])
        append_unique(generate_rule_mutations(base_passwords[:200], max_limit=15000))
        append_unique(generate_mask_candidates("?d?d?d?d", max_limit=10000))
        candidates = c_list

    fast_algos = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "ntlm", "mysql"}
    
    total_candidates_tested = 0
    t_crack_start = time.time()

    # 1. Crack fast unsalted targets
    unsalted_fast_targets = [t for t in targets if not t["salt"] and any(a[0] in fast_algos for a in t["candidate_algos"])]
    if unsalted_fast_targets:
        # Group targets by all possible algorithms they could be
        # target_lookup: {algo: {normalized_hash: [target_dict, ...]}}
        target_lookup: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for t in unsalted_fast_targets:
            for algo, d_name, m_code in t["candidate_algos"]:
                if algo in fast_algos:
                    norm = t["hash"].upper() if algo == "mysql" else t["hash"].lower()
                    target_lookup.setdefault(algo, {}).setdefault(norm, []).append(t)

        needed_algos = list(target_lookup.keys())

        for cand in candidates:
            total_candidates_tested += 1
            for algo in needed_algos:
                h = compute_fast_hash(algo, cand)
                if h and h in target_lookup[algo]:
                    for matched_target in target_lookup[algo][h]:
                        if not matched_target["cracked"]:
                            matched_target["cracked"] = True
                            matched_target["plaintext"] = cand
                            matched_target["algo"] = algo
                            meta = ALGO_DISPLAY_MAP.get(algo, (algo.upper(), 0))
                            matched_target["algo_display"] = meta[0]
                            matched_target["hashcat_mode"] = meta[1]
                            matched_target["time_cracked"] = round(time.time() - t_crack_start, 4)

            if all(t["cracked"] for t in unsalted_fast_targets):
                break

    # 2. Crack salted fast targets
    salted_fast_targets = [t for t in targets if t["salt"] and not t["cracked"] and any(a[0] in fast_algos for a in t["candidate_algos"])]
    for t in salted_fast_targets:
        for cand in candidates:
            total_candidates_tested += 1
            for algo, d_name, m_code in t["candidate_algos"]:
                if algo in fast_algos:
                    h = compute_fast_hash(algo, cand, t["salt"])
                    if h and h.lower() == t["hash"].lower():
                        t["cracked"] = True
                        t["plaintext"] = cand
                        t["algo"] = algo
                        t["algo_display"] = d_name
                        t["hashcat_mode"] = m_code
                        t["time_cracked"] = round(time.time() - t_crack_start, 4)
                        break
            if t["cracked"]:
                break

    # 3. Crack slow targets (bcrypt, apr1, sha512_crypt, etc.)
    slow_targets = [t for t in targets if not t["cracked"] and any(a[0] not in fast_algos for a in t["candidate_algos"])]
    for t in slow_targets:
        for cand in candidates[:1000]:  # Keep responsive for slow crypt algorithms
            total_candidates_tested += 1
            for algo, d_name, m_code in t["candidate_algos"]:
                if algo not in fast_algos:
                    if verify_slow_hash(algo, cand, t["hash"]):
                        t["cracked"] = True
                        t["plaintext"] = cand
                        t["algo"] = algo
                        t["algo_display"] = d_name
                        t["hashcat_mode"] = m_code
                        t["time_cracked"] = round(time.time() - t_crack_start, 4)
                        break
            if t["cracked"]:
                break

    total_time = max(time.time() - t_crack_start, 0.0001)
    crack_speed = round(total_candidates_tested / total_time)
    cracked_count = sum(1 for t in targets if t["cracked"])

    findings = []
    records = []

    for t in targets:
        if t["cracked"]:
            findings.append(f(
                "critical",
                f"Credentials Found: {t['user']}:{t['plaintext']}",
                f"Hash Cracked: {t['hash']} ({t['algo_display']}) in {t['time_cracked']}s. Plaintext: '{t['plaintext']}'",
                "Reset password immediately; enforce salted Argon2id/Bcrypt and minimum 16 characters passphrase."
            ))
            status_badge = "✓ CRACKED"
        else:
            status_badge = "✗ Exhausted"

        entropy_val = "—"
        if t["cracked"]:
            ent = calculate_entropy_metrics(t["plaintext"])
            entropy_val = f"{ent['entropy_bits']} b ({ent['rating']})"

        records.append({
            "User / ID": t["user"],
            "Hash": t["hash"][:24] + "..." if len(t["hash"]) > 28 else t["hash"],
            "Algorithm": f"{t['algo_display']} (-m {t['hashcat_mode']})",
            "Salt": t["salt"] or "none",
            "Status": status_badge,
            "Plaintext Password": t["plaintext"] if t["cracked"] else "—",
            "Entropy": entropy_val,
            "Time": f"{t['time_cracked']}s" if t["time_cracked"] is not None else "—",
        })

    if cracked_count == 0:
        findings.append(f(
            "pass",
            "No Hashes Cracked",
            f"Tested {total_candidates_tested} candidates against {len(targets)} hashes without match.",
            "Passwords may be complex or use uncracked custom salt/algorithm."
        ))

    return ok({
        "summary": {
            "Hashes Provided": len(targets),
            "Hashes Cracked": f"{cracked_count} / {len(targets)}",
            "Success Rate": f"{round((cracked_count / len(targets)) * 100, 1)}%",
            "Candidates Tested": f"{total_candidates_tested:,}",
            "Cracking Speed": f"{crack_speed:,} H/s",
            "Elapsed Time": f"{round(total_time, 2)}s",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["User / ID", "Hash", "Algorithm", "Salt", "Status", "Plaintext Password", "Entropy", "Time"],
    })
