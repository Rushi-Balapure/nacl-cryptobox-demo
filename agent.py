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

# --- CONFIGURATION ---
# Load Long-Term Agent Private Key
with open("agent.pri", "rb") as f:
    AGENT_PRI = nacl.signing.SigningKey(f.read(), encoder=nacl.encoding.HexEncoder)
    AGENT_PUB_HEX = AGENT_PRI.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()


def load_or_register_device():
    """
    Ensure this agent has a device_id by registering its public key with the server once.
    """
    if os.path.exists(DEVICE_ID_PATH):
        with open(DEVICE_ID_PATH, "r", encoding="utf-8") as f:
            device_id = f.read().strip()
            if device_id:
                return device_id

    # No device_id yet: register with server
    device_info = {
        "os": platform.system(),
        "release": platform.release(),
        "hostname": platform.node(),
    }
    payload = {
        "device_public_key": AGENT_PUB_HEX,
        "device_info": device_info,
    }
    print("[AGENT] Registering device with server...")
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

    # --- Step 3 (Receive) ---
    print("[AGENT] Requesting handshake...")
    response = requests.post(
        f"{SERVER_URL}/handshake/init",
        json={"device_id": device_id},
        timeout=5,
    )
    data = response.json()
    
    signed_envelope = base64.b64decode(data['signed_envelope'])

    # --- Step 4: Verify Server Signature ---
    try:
        verified_bytes = server_verify_key.verify(signed_envelope)
        server_payload = json.loads(verified_bytes.decode('utf-8'))
        print("[AGENT] Server Signature Verified.")
    except nacl.exceptions.BadSignatureError:
        print("[AGENT] Error: Fake Server Detected!")
        return

    # Extract Data
    challenge = base64.b64decode(server_payload['challenge'])
    server_eph_pub_bytes = base64.b64decode(server_payload['server_eph_pub'])
    server_eph_pub = nacl.public.PublicKey(server_eph_pub_bytes)
    session_id = server_payload['session_id']

    # --- Step 5: Generate Agent Ephemeral Keys ---
    agent_eph_pri = nacl.public.PrivateKey.generate()
    agent_eph_pub = agent_eph_pri.public_key

    # --- Step 6: Generate ECDH Key ---
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

    # --- Step 7: Solve Challenge ---
    # We define the solution as SHA256(challenge)
    challenge_response = nacl.hash.sha256(challenge)

    # --- Step 8: Prepare Inner Box (Crypto-Box) ---
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

    # --- Step 9: Prepare Outer Box ---
    outer_payload = {
        'session_id': session_id,
        'inner_box': base64.b64encode(encrypted_inner).decode('utf-8'),
        'agent_eph_pub': base64.b64encode(agent_eph_pub.encode()).decode('utf-8')
    }

    # Sign Outer Box with Agent Long-term Key
    outer_bytes = json.dumps(outer_payload).encode('utf-8')
    signed_outer = AGENT_PRI.sign(outer_bytes)

    # --- Step 10: Forward to Server ---
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

    # --- Secure message over established session key ---
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