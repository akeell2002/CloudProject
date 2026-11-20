import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.crypto.ed25519 import (
    canonical_json_hash,
    generate_keypair,
    sign_message,
    verify_signature,
)
from node.crypto.http_sig import (
    create_origin_http_signature,
    verify_origin_http_signature,
)


class TestCryptoPrimitives(unittest.TestCase):
    def test_ed25519_keypair_and_signing(self):
        priv, pub = generate_keypair()
        self.assertEqual(len(priv), 64)
        self.assertEqual(len(pub), 64)

        dict_a = {"domain": "evil.xyz", "seq": 10, "epoch": 1}
        dict_b = {"epoch": 1, "domain": "evil.xyz", "seq": 10}
        self.assertEqual(canonical_json_hash(dict_a), canonical_json_hash(dict_b))

        sig = sign_message(priv, dict_a)
        self.assertTrue(verify_signature(pub, dict_a, sig))

        tampered = {"domain": "innocent.edu", "seq": 10, "epoch": 1}
        self.assertFalse(verify_signature(pub, tampered, sig))

        _, other_pub = generate_keypair()
        self.assertFalse(verify_signature(other_pub, dict_a, sig))

    def test_origin_http_signature_verification(self):
        evil_priv, evil_pub = generate_keypair()
        accused_domain = "evil-spammer.com"
        known_keys = {accused_domain: evil_pub}

        payload = {"content": "Malicious phishing payload", "actor": "https://evil-spammer.com/user"}
        valid_sig = create_origin_http_signature(accused_domain, payload, evil_priv)

        self.assertTrue(verify_origin_http_signature(accused_domain, payload, valid_sig, known_keys))
        self.assertFalse(verify_origin_http_signature("innocent-university.edu", payload, valid_sig, known_keys))


if __name__ == "__main__":
    unittest.main()
