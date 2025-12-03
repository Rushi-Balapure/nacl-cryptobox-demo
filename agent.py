import requests
import nacl.signing
import nacl.public
import nacl.encoding
import nacl.secret
import nacl.hash
import nacl.bindings
import json
import base64
import platform
import os

SERVER_URL = "http://10.0.2.15:5000"
DEVICE_ID_PATH = "device_id.txt"

# REG_TOKEN is the out-of-band shared secret entered by the user.
# For this demo we read it from the environment or fall back to a static value.
REG_TOKEN = os.environ.get("REG_TOKEN", "demo-reg-token-1234")

# --- CONFIGURATION ---
# Load Long-Term Agent Private Key
with open("agent.pri", "rb") as f:
    AGENT_PRI = nacl.signing.SigningKey(f.read(), encoder=nacl.encoding.HexEncoder)
    AGENT_PUB_HEX = AGENT_PRI.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()


def derive_binding_key(token: str) -> bytes:
    """
    Derive a 32-byte symmetric key from the REG_TOKEN using blake2b.
    """
    return nacl.hash.blake2b(
        token.encode("utf-8"),
        digest_size=32,
        encoder=nacl.encoding.RawEncoder,
    )


def compute_reg_handle(binding_key: bytes) -> str:
    """
    Compute an opaque registration handle from the binding key.
    This handle is safe to send over the network; the REG_TOKEN itself is not.
    """
    return nacl.hash.blake2b(
        binding_key,
        digest_size=16,
        encoder=nacl.encoding.HexEncoder,
    ).decode()


def load_or_register_device():
    """
    Phase I – Steps 2 & 3 (Agent side):
    Ensure this agent has a device_id by registering its public key with the server once,
    using an encrypted payload bound to the REG_TOKEN.
    """
    if os.path.exists(DEVICE_ID_PATH):
        with open(DEVICE_ID_PATH, "r", encoding="utf-8") as f:
            device_id = f.read().strip()
            if device_id:
                return device_id

    # No device_id yet: secure registration with encrypted payload bound to REG_TOKEN
    device_info = {
        "os": platform.system(),
        "release": platform.release(),
        "hostname": platform.node(),
    }

    binding_key = derive_binding_key(REG_TOKEN)
    reg_handle = compute_reg_handle(binding_key)

    inner_payload = {
        "device_public_key": AGENT_PUB_HEX,
        "device_info": device_info,
    }

    box = nacl.secret.SecretBox(binding_key)
    encrypted = box.encrypt(json.dumps(inner_payload).encode("utf-8"))

    payload = {
        "reg_handle": reg_handle,
        "encrypted_payload": base64.b64encode(encrypted).decode("utf-8"),
    }

    print("[AGENT] Registering device with server (encrypted binding)...")
    res = requests.post(f"{SERVER_URL}/register_device", json=payload, timeout=5)
    res.raise_for_status()
    data = res.json()
    device_id = data["device_id"]

    with open(DEVICE_ID_PATH, "w", encoding="utf-8") as f:
        f.write(device_id)

    print(f"[AGENT] Registered device_id={device_id}")
    return device_id


def fetch_server_verify_key():
    """
    Fetch the server's long-term public key from the /server_pub endpoint.
    """
    print("[AGENT] Fetching server public key...")
    res = requests.get(f"{SERVER_URL}/server_pub", timeout=5)
    res.raise_for_status()
    data = res.json()
    server_pub_hex = data["server_public_key"]
    return nacl.signing.VerifyKey(server_pub_hex, encoder=nacl.encoding.HexEncoder)


def run_agent():
    device_id = load_or_register_device()
    server_verify_key = fetch_server_verify_key()

    # Phase II – Step 5: Request CHALLENGE and server-ephemeral.pub from the server.
    print("[AGENT] Requesting handshake...")
    response = requests.post(
        f"{SERVER_URL}/handshake/init",
        json={"device_id": device_id},
        timeout=5,
    )
    data = response.json()
    
    signed_envelope = base64.b64decode(data['signed_envelope'])

    # Phase II – Step 6: Verify server signature and parse CHALLENGE + server-ephemeral.pub.
    try:
        verified_bytes = server_verify_key.verify(signed_envelope)
        server_payload = json.loads(verified_bytes.decode('utf-8'))
        print("[AGENT] Server Signature Verified.")
    except nacl.exceptions.BadSignatureError:
        print("[AGENT] Error: Fake Server Detected!")
        return

    # Extract Data (CHALLENGE, server-ephemeral.pub, session_id)
    challenge = base64.b64decode(server_payload['challenge'])
    server_eph_pub_bytes = base64.b64decode(server_payload['server_eph_pub'])
    server_eph_pub = nacl.public.PublicKey(server_eph_pub_bytes)
    session_id = server_payload['session_id']

    # Phase II – Step 7: Generate agent-ephemeral key pair.
    agent_eph_pri = nacl.public.PrivateKey.generate()
    agent_eph_pub = agent_eph_pri.public_key

    # Phase II – Step 8: Derive ECDH-based session key.
    # crypto_scalarmult(my_priv, their_pub)
    shared_point = nacl.bindings.crypto_scalarmult(
        agent_eph_pri.encode(),
        server_eph_pub.encode()
    )
    # KDF to get symmetric key (raw 32 bytes, not hex-encoded)
    ecdh_key = nacl.hash.blake2b(
        shared_point,
        digest_size=32,
        encoder=nacl.encoding.RawEncoder,
    )

    # Phase II – Step 9: Solve CHALLENGE to produce CHALLENGE_RESPONSE.
    # We define the solution as SHA256(challenge)
    challenge_response = nacl.hash.sha256(challenge)

    # Phase II – Step 10: Prepare Inner Box (Crypto-Box).
    inner_payload = {
        'challenge_response': base64.b64encode(challenge_response).decode('utf-8'),
        'agent_pub_long_term': AGENT_PUB_HEX,
        'device_attestations': {
            'os': platform.system(),
            'release': platform.release(),
            'hostname': platform.node()
        },
        'secret_message': "Hello Server, this is a secure trust channel!"
    }
    
    # Encrypt using the Symmetric ECDH Key (XSalsa20-Poly1305)
    box = nacl.secret.SecretBox(ecdh_key)
    encrypted_inner = box.encrypt(json.dumps(inner_payload).encode('utf-8'))

    # Phase II – Step 11: Prepare Outer Box (wrap Inner Box + agent-ephemeral.pub).
    outer_payload = {
        'session_id': session_id,
        'inner_box': base64.b64encode(encrypted_inner).decode('utf-8'),
        'agent_eph_pub': base64.b64encode(agent_eph_pub.encode()).decode('utf-8')
    }

    # Sign Outer Box with Agent Long-term Key
    outer_bytes = json.dumps(outer_payload).encode('utf-8')
    signed_outer = AGENT_PRI.sign(outer_bytes)

    # Phase II – Step 12: Forward Outer Box (signed) to the server.
    final_payload = {
        'outer_envelope': base64.b64encode(signed_outer).decode('utf-8'),
        'device_id': device_id,
    }

    print("[AGENT] Sending encrypted proofs...")
    res = requests.post(
        f"{SERVER_URL}/handshake/verify",
        json=final_payload,
        timeout=5,
    )
    verify_result = res.json()
    print(f"[AGENT] Server Handshake Response: {verify_result}")

    if verify_result.get("status") != "trusted":
        print("[AGENT] Handshake failed; aborting secure message.")
        return

    session_id = verify_result["session_id"]

    # Post-Handshake: Use established session key for secure application messages.
    secure_box = nacl.secret.SecretBox(ecdh_key)
    message = "Hello Server, this is a post-handshake secure message from the agent."
    ciphertext = secure_box.encrypt(message.encode("utf-8"))

    secure_payload = {
        "session_id": session_id,
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }

    print("[AGENT] Sending secure message over session...")
    secure_res = requests.post(
        f"{SERVER_URL}/secure_message",
        json=secure_payload,
        timeout=5,
    )
    print(f"[AGENT] Secure message response: {secure_res.json()}")

if __name__ == "__main__":
    run_agent()