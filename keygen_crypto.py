import binascii

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_identity(name: str) -> None:
    """
    Generate an Ed25519 identity and store raw keys as hex.

    This mirrors the original NaCl-based keygen but uses the
    `cryptography` library instead of PyNaCl.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Raw 32-byte Ed25519 keys, hex-encoded for storage (same size as NaCl)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    with open(f"{name}.pri", "wb") as f:
        f.write(binascii.hexlify(private_bytes))

    with open(f"{name}.pub", "wb") as f:
        f.write(binascii.hexlify(public_bytes))

    print(f"Generated {name} keys.")


if __name__ == "__main__":
    # Separate names so they don't clash with the NaCl-based demo keys
    generate_identity("server_crypto")
    generate_identity("agent_crypto")


