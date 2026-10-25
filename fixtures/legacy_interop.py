#!/usr/bin/env python3
"""Legacy sample signer used only by interoperability tests.

Mirrors create_http_message_signature and create_ed25519_signature from
visa/trusted-agent-protocol tap-agent/agent_app.py at 16d59bdf.
"""

import base64
import json
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding


def legacy_params(authority: str, path: str, keyid: str, nonce: str, created: int, expires: int, tag: str, alg: str) -> str:
    return (
        f'"@authority": {authority}\n'
        f'"@path": {path}\n'
        f'"@signature-params": ("@authority" "@path"); created={created}; expires={expires}; '
        f'keyId="{keyid}"; alg="{alg}"; nonce="{nonce}"; tag="{tag}"'
    )


def sign_ed25519(seed_b64: str, base: str) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64))
    return base64.b64encode(key.sign(base.encode("utf-8"))).decode("utf-8")


def verify_ed25519(public_b64: str, signature_b64: str, base: str) -> None:
    key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
    key.verify(base64.b64decode(signature_b64), base.encode("utf-8"))


def sign_rsa(pem: str, base: str) -> str:
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    signature = key.sign(
        base.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_rsa(pem: str, signature_b64: str, base: str) -> None:
    key = serialization.load_pem_public_key(pem.encode("utf-8"))
    key.verify(
        base64.b64decode(signature_b64),
        base.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def main() -> None:
    request = json.load(sys.stdin)
    op = request["op"]
    if op == "base":
        base = legacy_params(
            request["authority"],
            request["path"],
            request["keyId"],
            request["nonce"],
            int(request["created"]),
            int(request["expires"]),
            request["tag"],
            request["alg"],
        )
        json.dump({"base": base}, sys.stdout)
    elif op == "sign-ed25519":
        json.dump({"signature": sign_ed25519(request["seed"], request["base"])}, sys.stdout)
    elif op == "verify-ed25519":
        verify_ed25519(request["public"], request["signature"], request["base"])
        json.dump({"ok": True}, sys.stdout)
    elif op == "sign-rsa":
        json.dump({"signature": sign_rsa(request["pem"], request["base"])}, sys.stdout)
    elif op == "verify-rsa":
        verify_rsa(request["pem"], request["signature"], request["base"])
        json.dump({"ok": True}, sys.stdout)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
