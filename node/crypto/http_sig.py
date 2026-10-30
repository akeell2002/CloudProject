import json
import hashlib
from typing import Dict, Any


def create_origin_http_signature(
    domain: str,
    payload: Dict[str, Any],
    origin_private_key_hex: str
) -> Dict[str, str]:
    """
    Simulates a W3C ActivityPub HTTP Signature signed by the origin server.
    Used by simulations and attackers to generate realistic signed payloads.
    """
    from node.crypto.ed25519 import sign_message, canonical_json_hash

    payload_hash = canonical_json_hash(payload).hex()
    signing_string = f"origin_domain:{domain}\ndigest:SHA-256={payload_hash}"
    sig = sign_message(origin_private_key_hex, signing_string.encode("utf-8"))

    return {
        "keyId": f"https://{domain}/actor#main-key",
        "algorithm": "ed25519-sha256",
        "headers": "origin_domain digest",
        "signature": sig,
        "digest": f"SHA-256={payload_hash}"
    }


def verify_origin_http_signature(
    accused_domain: str,
    evidence_payload_json: str,
    origin_signature_info: Dict[str, str],
    known_domain_public_keys: Dict[str, str]
) -> bool:
    """
    Anti-Framing Verification:
    Verifies that the submitted abusive post was authentically signed by the
    private key of the accused domain.

    If a rogue leader fabricates a fake post attributing abuse to an innocent domain,
    it cannot produce a valid signature under that domain's private key.
    """
    from node.crypto.ed25519 import verify_signature, canonical_json_hash

    if accused_domain not in known_domain_public_keys:
        # Unknown domain public key - cannot cryptographically verify origin
        return False

    domain_pubkey = known_domain_public_keys[accused_domain]

    try:
        if isinstance(evidence_payload_json, str):
            payload_data = json.loads(evidence_payload_json)
        else:
            payload_data = evidence_payload_json

        actual_digest = canonical_json_hash(payload_data).hex()
        expected_digest = origin_signature_info.get("digest", "").replace("SHA-256=", "")

        # 1. Did someone tamper with the post text?
        if actual_digest != expected_digest:
            return False

        # 2. Was it genuinely signed by the accused domain?
        signing_string = f"origin_domain:{accused_domain}\ndigest:SHA-256={actual_digest}"
        signature = origin_signature_info.get("signature", "")

        return verify_signature(domain_pubkey, signing_string.encode("utf-8"), signature)
    except Exception:
        return False
