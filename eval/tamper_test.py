"""
tamper_test.py  --  demonstrable log-integrity check for Cortex-Chain

Proves the tamper-evidence claim with a concrete, defensible outcome (no
percentages): change ONE byte of an archived log and the recorded SHA-256 no
longer matches on verification.

Two parts:
  A. Single-artifact integrity -- the core claim. Hash the exact archived
     bytes, store the digest, then flip one byte and re-verify -> FAIL.
  B. Ledger-chain cascade -- mirrors cortex_blockchain.calculate_hash: each
     block's hash chains the previous one, so tampering block N breaks N and
     every block after it, not just N.

Runs fully offline. No AWS, no network.
"""

import hashlib
import json

SEED = "0" * 64  # genesis, same as cortex_blockchain.py


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def chain_hash(content: str, previous_hash: str) -> str:
    # identical to cortex_blockchain.calculate_hash
    return hashlib.sha256(f"{content}{previous_hash}".encode()).hexdigest()


def make_archived_log():
    """A compliance package shaped like cortex_api.py archives to S3."""
    pkg = {
        "timestamp": "2026-08-31T10:15:00",
        "analyst_id": "arjun-soc-intern",
        "ai_analysis": "VERDICT: BRUTE_FORCE - 80 failures from 45.61.148.22 in 40s.",
        "raw_log": {"EventID": 4625, "TargetUserName": "administrator",
                    "IpAddress": "45.61.148.22", "failure_count": 80},
    }
    return json.dumps(pkg, indent=2).encode()  # exact archived bytes


def part_a():
    print("=" * 60)
    print("PART A -- single-artifact integrity")
    print("=" * 60)
    archived = make_archived_log()
    recorded = sha256_bytes(archived)
    print(f"Archived bytes: {len(archived)}")
    print(f"Recorded SHA-256: {recorded}")

    # verify untouched
    ok = sha256_bytes(archived) == recorded
    print(f"\nVerify (untouched): {'PASS' if ok else 'FAIL'}  "
          f"-> {'matches' if ok else 'MISMATCH'}")

    # flip exactly one byte
    idx = archived.find(b"80")  # the failure_count value
    tampered = bytearray(archived)
    tampered[idx] = ord("9")    # '8' -> '9': 80 becomes 90, one byte changed
    tampered = bytes(tampered)
    changed = sum(a != b for a, b in zip(archived, tampered))
    new_hash = sha256_bytes(tampered)
    print(f"\nBytes changed: {changed}")
    print(f"Recomputed SHA-256: {new_hash}")
    verified = new_hash == recorded
    print(f"Verify (1 byte changed): {'PASS' if verified else 'FAIL'}  "
          f"-> {'matches' if verified else 'MISMATCH detected'}")
    assert not verified, "one-byte change must break the hash"
    return recorded, new_hash


def part_b():
    print("\n" + "=" * 60)
    print("PART B -- ledger-chain cascade (cortex_blockchain style)")
    print("=" * 60)
    logs = [
        json.dumps({"file": "alert_1.json", "failure_count": 80}),
        json.dumps({"file": "alert_2.json", "failure_count": 3}),
        json.dumps({"file": "alert_3.json", "failure_count": 55}),
    ]
    # build ledger
    ledger, prev = [], SEED
    for content in logs:
        h = chain_hash(content, prev)
        ledger.append({"content": content, "previous_hash": prev, "current_hash": h})
        prev = h
    print("Ledger built with", len(ledger), "blocks.")

    # tamper block index 1 (the middle one): 3 -> 300 failures
    tampered_logs = list(logs)
    tampered_logs[1] = json.dumps({"file": "alert_2.json", "failure_count": 300})

    # Re-verify by walking the chain: each block's hash is recomputed from its
    # content AND the PREVIOUS RECOMPUTED hash, then compared to what's stored.
    # This is what makes it a chain -- a break propagates forward.
    print("\nRe-verifying chain after tampering block 2 (failure_count 3 -> 300):")
    prev, first_break = SEED, None
    for i, content in enumerate(tampered_logs):
        recomputed = chain_hash(content, prev)
        stored = ledger[i]["current_hash"]
        status = "OK" if recomputed == stored else "BROKEN"
        if status == "BROKEN" and first_break is None:
            first_break = i
        print(f"  block {i+1}: {status}")
        prev = recomputed  # carry the recomputed hash forward -> cascade
    print(f"\nFirst broken block: #{first_break + 1}. "
          f"Because each block hashes the previous block's hash, the break "
          f"cascades to every block after it.")
    assert first_break == 1


if __name__ == "__main__":
    part_a()
    part_b()
    print("\nTamper detection demonstrated: any single-byte change is caught.")
