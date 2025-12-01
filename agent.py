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

SERVER_URL = "http://127.0.0.1:5000"

# --- CONFIGURATION ---
# Load Long-Term Agent Private Key
with open("agent.pri", "rb") as f:
    AGENT_PRI = nacl.signing.SigningKey(f.read(), encoder=nacl.encoding.HexEncoder)
    AGENT_PUB_HEX = AGENT_PRI.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

# Load Known Server Public Key
with open("server.pub", "rb") as f:
    SERVER_PUB_KEY = nacl.signing.VerifyKey(f.read(), encoder=nacl.encoding.HexEncoder)

def run_agent():
    # --- Step 3 (Receive) ---
    print("[AGENT] Requesting handshake...")
    response = requests.post(f"{SERVER_URL}/handshake/init")
    data = response.json()
    
    signed_envelope = base64.b64decode(data['signed_envelope'])

    # --- Step 4: Verify Server Signature ---
    try:
        verified_bytes = SERVER_PUB_KEY.verify(signed_envelope)
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
    # KDF to get symmetric key
    ecdh_key = nacl.hash.blake2b(shared_point, digest_size=32)

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
        'outer_envelope': base64.b64encode(signed_outer).decode('utf-8')
    }

    print("[AGENT] Sending encrypted proofs...")
    res = requests.post(f"{SERVER_URL}/handshake/verify", json=final_payload)
    print(f"[AGENT] Server Response: {res.json()}")

if __name__ == "__main__":
    run_agent()