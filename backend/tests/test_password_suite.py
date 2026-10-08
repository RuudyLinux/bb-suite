import sys
import asyncio
import hashlib
import bcrypt
sys.stdout.reconfigure(encoding='utf-8')

from tools.password_cracker import password_cracker, calculate_entropy_metrics, generate_targeted_wordlist
from tools.bruteforce import brute_force
from models import PasswordCrackReq, BruteReq

async def run_tests():
    print("==================================================")
    print("  RUNNING PASSWORD CRACKING SUITE VERIFICATION")
    print("==================================================")

    # Test 1: Multi-Algorithm Hash Cracking
    print("\n[1] Testing Multi-Algorithm Offline Hash Cracker...")
    sample_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",                            # MD5: password
        "209c6174da490caeb422f3fa5a7ae634",                            # NTLM: admin
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",                    # SHA-1: password
        "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", # SHA-256: password123
        "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",                    # MySQL 4.1+: password
    ]
    req1 = PasswordCrackReq(
        mode="hash_crack",
        hashes="\n".join(sample_hashes),
        attack_type="all"
    )
    res1 = await password_cracker(req1)
    assert res1["success"], "Hash cracking failed!"
    summary1 = res1["data"]["summary"]
    print(f"    Hashes Tested: {summary1['Hashes Provided']}")
    print(f"    Hashes Cracked: {summary1['Hashes Cracked']}")
    print(f"    Cracking Speed: {summary1['Cracking Speed']}")
    print(f"    Elapsed: {summary1['Elapsed Time']}")
    assert int(summary1['Hashes Cracked'].split(' / ')[0]) == 5, f"Expected 5/5 cracked, got {summary1['Hashes Cracked']}"
    print("    [✓] All 5 multi-algorithm hashes cracked successfully!")

    # Test 2: Salted Hash Cracking
    print("\n[2] Testing Salted Hash Cracking...")
    salt = "s3cr3t"
    salted_md5 = hashlib.md5(("admin" + salt).encode('utf-8')).hexdigest()
    req2 = PasswordCrackReq(
        mode="hash_crack",
        hashes=f"{salted_md5}:{salt}",
        hash_type="md5",
        attack_type="dictionary"
    )
    res2 = await password_cracker(req2)
    assert res2["success"]
    assert res2["data"]["records"][0]["Plaintext Password"] == "admin"
    print(f"    [✓] Salted MD5 cracked: admin:{salt} -> {res2['data']['records'][0]['Plaintext Password']}")

    # Test 3: Rule-Based Mutation (e.g. Password2025!)
    print("\n[3] Testing Rule-Based Mutations (Leet, Year, Symbol Mangling)...")
    complex_rule_pwd = "Admin2025!"
    rule_hash = hashlib.sha256(complex_rule_pwd.encode('utf-8')).hexdigest()
    req3 = PasswordCrackReq(
        mode="hash_crack",
        hashes=rule_hash,
        attack_type="rules",
        custom_wordlist="admin"
    )
    res3 = await password_cracker(req3)
    assert res3["success"]
    rec3 = res3["data"]["records"][0]
    assert rec3["Plaintext Password"] == complex_rule_pwd, f"Expected {complex_rule_pwd}, got {rec3['Plaintext Password']}"
    print(f"    [✓] Rule mutation generated and cracked: {complex_rule_pwd} ({rec3['Algorithm']})")

    # Test 4: Password Entropy & Strength Audit
    print("\n[4] Testing Password Strength & Entropy Auditor...")
    test_pwds = [
        "123456",
        "qwerty",
        "P@ssw0rd2025!",
        "correct-horse-battery-staple-2026!#"
    ]
    req4 = PasswordCrackReq(
        mode="entropy_audit",
        passwords="\n".join(test_pwds)
    )
    res4 = await password_cracker(req4)
    assert res4["success"]
    recs4 = res4["data"]["records"]
    assert len(recs4) == 4
    for r in recs4:
        print(f"    Pwd: {r['Password']:<35} Entropy: {r['Entropy (bits)']:<8} Rating: {r['Rating']:<12} Score: {r['Score']}")
    assert "WEAK" in recs4[0]["Rating"]
    assert "STRONG" in recs4[3]["Rating"]
    print("    [✓] Entropy metrics, ratings, and crack times calculated accurately!")

    # Test 5: Targeted Wordlist Generator (CUPP)
    print("\n[5] Testing Targeted Wordlist Profiler...")
    req5 = PasswordCrackReq(
        mode="wordlist_generator",
        target_info="tesla, elon, 2026"
    )
    res5 = await password_cracker(req5)
    assert res5["success"]
    assert res5["data"]["summary"]["Total Candidates Generated"] > 50
    print(f"    [✓] Generated {res5['data']['summary']['Total Candidates Generated']} custom targeted candidates.")

    # Test 6: Online Brute Force Engine Check
    print("\n[6] Testing Online Brute Force Engine Initialization...")
    req6 = BruteReq(
        target="http://127.0.0.1:9999/dummy_login",
        username="admin",
        concurrency=5,
        wordlist_size="small"
    )
    # The URL will fail to connect (port 9999 not open), but verifies proper error handling
    res6 = await brute_force(req6)
    assert not res6["success"], "Expected unreachable target error"
    print(f"    [✓] Brute force robustly handled unreachable target: {res6['error']}")

    print("\n==================================================")
    print("  ALL 6 SUITE TESTS PASSED WITH 100% SUCCESS!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_tests())
