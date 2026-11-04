import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.crypto.ed25519 import (
    generate_keypair,
    sign_message,
    verify_signature,
    canonical_json_hash
)
from node.crypto.http_sig import (
    create_origin_http_signature,
    verify_origin_http_signature
)


def test_ed25519_keypair_and_signing():
    """Verify digital signature creation, canonical hashing, and forgery detection."""
    priv, pub = generate_keypair()
    assert len(priv) == 64
    assert len(pub) == 64

    # 1. Deterministic Canonical Hash check (key order invariance)
    dict_a = {"domain": "evil.xyz", "seq": 10, "epoch": 1}
    dict_b = {"epoch": 1, "domain": "evil.xyz", "seq": 10}
    assert canonical_json_hash(dict_a) == canonical_json_hash(dict_b)
    print("  [PASS] 1. Deterministic Canonical JSON Hashing verified")

    # 2. Genuine signature verification
    sig = sign_message(priv, dict_a)
    assert verify_signature(pub, dict_a, sig) is True
    print("  [PASS] 2. Ed25519 digital signature verified")

    # 3. Tampered payload rejection
    tampered_dict = {"domain": "innocent.edu", "seq": 10, "epoch": 1}
    assert verify_signature(pub, tampered_dict, sig) is False
    print("  [PASS] 3. Tampered message correctly rejected")

    # 4. Forged signature rejection (using another node's public key)
    _, other_pub = generate_keypair()
    assert verify_signature(other_pub, dict_a, sig) is False
    print("  [PASS] 4. Signature forgery correctly detected and rejected")


def test_origin_http_sig_anti_framing():
    """Verify that framing attacks against innocent servers are caught and rejected."""
    evil_priv, evil_pub = generate_keypair()
    accused_domain = "evil-spammer.com"
    known_keys = {accused_domain: evil_pub}

    payload = {"content": "Malicious phishing payload", "actor": "https://evil-spammer.com/user"}
    valid_sig = create_origin_http_signature(accused_domain, payload, evil_priv)

    # 1. Authentic spam post verified against author's key
    assert verify_origin_http_signature(accused_domain, payload, valid_sig, known_keys) is True
    print("  [PASS] 5. Origin HTTP signature verified for genuine post")

    # 2. Framing attack caught (someone attributing the post to an innocent domain)
    innocent_domain = "innocent-university.edu"
    assert verify_origin_http_signature(innocent_domain, payload, valid_sig, known_keys) is False
    print("  [PASS] 6. Anti-Framing Defense verified: spoofed attribution rejected")


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 1 FACTOR: CRYPTOGRAPHY & HTTP SIGNATURES      ")
    print("=======================================================")
    test_ed25519_keypair_and_signing()
    test_origin_http_sig_anti_framing()
    print("=======================================================")
    print("   ALL CRYPTOGRAPHY MODULES PASS 100%!                ")
    print("=======================================================\n")
