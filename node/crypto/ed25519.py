
import json
import hashlib
from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> Tuple[str, str]:
    """
    Generates an Ed25519 private/public keypair.
    Returns: (private_key_hex, public_key_hex)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes.hex(), pub_bytes.hex()


def canonical_json_hash(data: Union[dict, list, str, bytes]) -> bytes:
    """
    Produces a deterministic SHA-256 hash.
    Ensures dictionary keys are sorted so identical proposals
    produce the exact same cryptographic hash across all nodes.
    """
    if isinstance(data, (dict, list)):
        canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).digest()
    elif isinstance(data, str):
        return hashlib.sha256(data.encode("utf-8")).digest()
    elif isinstance(data, bytes):
        return hashlib.sha256(data).digest()
    else:
        raise ValueError(f"Unsupported data type for hashing: {type(data)}")


def sign_message(private_key_hex: str, message: Union[bytes, str, dict]) -> str:
    """
    Signs a message using the node's Ed25519 private key.
    Returns the signature as a hex string.
    """
    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    if isinstance(message, (dict, list)):
        digest = canonical_json_hash(message)
    elif isinstance(message, str):
        digest = message.encode("utf-8")
    else:
        digest = message

    signature = private_key.sign(digest)
    return signature.hex()


def verify_signature(public_key_hex: str, message: Union[bytes, str, dict], signature_hex: str) -> bool:
    """
    Verifies an Ed25519 signature against the message and public key.
    Returns True if valid, False if forged or tampered.
    """
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

        if isinstance(message, (dict, list)):
            digest = canonical_json_hash(message)
        elif isinstance(message, str):
            digest = message.encode("utf-8")
        else:
            digest = message

        public_key.verify(sig_bytes, digest)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False