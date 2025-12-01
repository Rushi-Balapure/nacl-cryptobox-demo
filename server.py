from flask import Flask, request, jsonify
import nacl.signing
import nacl.public
import nacl.encoding
import nacl.secret
import nacl.hash
import nacl.utils
import nacl.bindings
import json
import base64
import os
import uuid

app = Flask(__name__)

# --- CONFIGURATION ---
# Load Long-Term Server Private Key
with open("server.pri", "rb") as f:
    SERVER_PRI = nacl.signing.SigningKey(f.read(), encoder=nacl.encoding.HexEncoder)

# Simple on-disk device registry (for demo purposes only)
DEVICE_REGISTRY_PATH = "devices.json"


def load_device_registry():
    """Load device registry from disk."""
    if not os.path.exists(DEVICE_REGISTRY_PATH):
        return {}
    with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_device_registry(registry):
    """Persist device registry to disk."""
    with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)


# In-memory cache of devices: device_id -> {public_key_hex, info, revoked}
devices = load_device_registry()

# Store session data (In prod, use Redis/DB). Maps session_id ->
#   {
#       'challenge': bytes,
#       'server_eph_pri': PrivateKey,
#       'device_id': str,
#       'ecdh_key': bytes | None
#   }
session_store = {}


@app.route("/register_device", methods=["POST"])
def register_device():
    """
    Step 2: Device registration.

    Expects JSON:
    {
        "device_public_key": "<hex-encoded Ed25519 verify key>",
        "device_info": {...}
    }
    """
    data = request.json or {}
    device_pub = data.get("device_public_key")
    device_info = data.get("device_info", {})

    if not device_pub:
        return jsonify({"error": "device_public_key is required"}), 400

    # Basic sanity check: hex string length for Ed25519 public key (32 bytes -> 64 hex chars)
    if not isinstance(device_pub, str) or len(device_pub) != 64:
        return jsonify({"error": "device_public_key must be a 64-char hex string"}), 400

    device_id = uuid.uuid4().hex
    devices[device_id] = {
        "public_key_hex": device_pub,
        "info": device_info,
        "revoked": False,
    }
    save_device_registry(devices)

    return jsonify(
        {
            "device_id": device_id,
            "message": "Device registered",
        }
    )

@app.route('/handshake/init', methods=['POST'])
def init_handshake():
    """ Step 2 & 3: Generate Challenge and send Signed Packet for a given device """

    data = request.json or {}
    device_id = data.get("device_id")
    if not device_id:
        return jsonify({"error": "device_id is required"}), 400

    device_record = devices.get(device_id)
    if not device_record or device_record.get("revoked"):
        return jsonify({"error": "Unknown or revoked device"}), 403

    # 2. Generate Challenge and Ephemeral Keypair (Curve25519)
    challenge = nacl.utils.random(32)
    server_eph_pri = nacl.public.PrivateKey.generate()
    server_eph_pub = server_eph_pri.public_key

    session_id = base64.b64encode(nacl.utils.random(8)).decode('utf-8')

    # Store private parts for later verification
    session_store[session_id] = {
        'challenge': challenge,
        'server_eph_pri': server_eph_pri,
        'device_id': device_id,
        'ecdh_key': None,
    }

    # Prepare payload
    payload = {
        'session_id': session_id,
        'challenge': base64.b64encode(challenge).decode('utf-8'),
        'server_eph_pub': base64.b64encode(server_eph_pub.encode()).decode('utf-8')
    }

    # 3. Sign the payload using Server Long-term Private Key
    # We dump JSON to bytes, then sign it.
    message_bytes = json.dumps(payload).encode('utf-8')
    signed = SERVER_PRI.sign(message_bytes)

    # Return the signed message (encoded for transport)
    return jsonify({
        'signed_envelope': base64.b64encode(signed).decode('utf-8')
    })

@app.route('/handshake/verify', methods=['POST'])
def verify_handshake():
    """ Step 11 - 15: Verify Agent Response """
    data = request.json or {}
    outer_envelope_b64 = data.get('outer_envelope')
    device_id = data.get('device_id')

    if not outer_envelope_b64 or not device_id:
        return jsonify({"status": "failed", "error": "outer_envelope and device_id are required"}), 400

    device_record = devices.get(device_id)
    if not device_record or device_record.get("revoked"):
        return jsonify({"status": "failed", "error": "Unknown or revoked device"}), 403

    device_pub_hex = device_record["public_key_hex"]
    verify_key = nacl.signing.VerifyKey(device_pub_hex, encoder=nacl.encoding.HexEncoder)

    outer_envelope = base64.b64decode(outer_envelope_b64)

    try:
        # 11. Verify signature using Agent's Long-term Public Key
        # If verify fails, it raises BadSignatureError
        verified_data_bytes = verify_key.verify(outer_envelope)
        outer_box_content = json.loads(verified_data_bytes.decode('utf-8'))
        
        session_id = outer_box_content['session_id']
        if session_id not in session_store:
            return "Session invalid", 400

        # Retrieve stored context
        server_eph_pri = session_store[session_id]['server_eph_pri']
        original_challenge = session_store[session_id]['challenge']

        # Extract Agent Ephemeral Public Key
        agent_eph_pub_bytes = base64.b64decode(outer_box_content['agent_eph_pub'])
        agent_eph_pub = nacl.public.PublicKey(agent_eph_pub_bytes)

        # 12. Compute ECDH Key (Shared Secret)
        # ECDH(server_pri, agent_pub)
        # Note: NaCl Box does hashing internally, but to strictly follow "derive key", we do this:
        shared_point = nacl.bindings.crypto_scalarmult(
            server_eph_pri.encode(),
            agent_eph_pub.encode()
        )
        # KDF: Hash the point to get a safe symmetric key (blake2b), raw 32 bytes
        ecdh_key = nacl.hash.blake2b(
            shared_point,
            digest_size=32,
            encoder=nacl.encoding.RawEncoder,
        )

        # Save derived session key for later secure API calls
        session_store[session_id]['ecdh_key'] = ecdh_key

        # 13. Decrypt Inner Box (Crypto-Box)
        # We use SecretBox (Symmetric) because we derived the key manually via ECDH
        box = nacl.secret.SecretBox(ecdh_key)
        encrypted_inner = base64.b64decode(outer_box_content['inner_box'])
        
        decrypted_bytes = box.decrypt(encrypted_inner)
        inner_data = json.loads(decrypted_bytes.decode('utf-8'))

        print(f"\n[SERVER] Decrypted Inner Data: {inner_data}")

        # 14. Verify Agent ID match (Anti-MITM)
        # Compare the ID inside the encrypted box with the one registered for this device
        agent_pub_inside = inner_data['agent_pub_long_term']

        if agent_pub_inside != device_pub_hex:
            raise Exception("MITM DETECTED: Outer signature key does not match Inner encrypted ID")

        # 15. Verify Challenge Response
        challenge_response = base64.b64decode(inner_data['challenge_response'])
        # Simple verification: Check if response is SHA256(challenge)
        expected_response = nacl.hash.sha256(original_challenge)
        
        if challenge_response != expected_response:
            raise Exception("Challenge Failed")

        print("[SERVER] SUCCESS: Device Verified and Trusted.")
        print(f"[SERVER] Device Info: {inner_data['device_attestations']}")
        print(f"[SERVER] Secret Message: {inner_data['secret_message']}")

        return jsonify(
            {
                "status": "trusted",
                "message": "Connection established",
                "session_id": session_id,
            }
        )

    except Exception as e:
        print(f"[SERVER] ERROR: {str(e)}")
        return jsonify({"status": "failed", "error": str(e)}), 403


@app.route("/secure_message", methods=["POST"])
def secure_message():
    """
    Example secure endpoint that uses the established session key.

    Expects JSON:
    {
        "session_id": "...",
        "ciphertext": "<base64-encoded SecretBox ciphertext>"
    }
    """
    data = request.json or {}
    session_id = data.get("session_id")
    ciphertext_b64 = data.get("ciphertext")

    if not session_id or not ciphertext_b64:
        return jsonify({"error": "session_id and ciphertext are required"}), 400

    session = session_store.get(session_id)
    if not session or not session.get("ecdh_key"):
        return jsonify({"error": "Unknown or untrusted session"}), 403

    box = nacl.secret.SecretBox(session["ecdh_key"])
    ciphertext = base64.b64decode(ciphertext_b64)

    try:
        plaintext_bytes = box.decrypt(ciphertext)
        plaintext = plaintext_bytes.decode("utf-8")
        print(f"[SERVER] Received secure message for session {session_id}: {plaintext}")
        return jsonify({"status": "ok", "echo": plaintext})
    except Exception as e:
        print(f"[SERVER] ERROR while decrypting secure message: {e}")
        return jsonify({"status": "failed", "error": "Decryption failed"}), 400

if __name__ == '__main__':
    print("Server running on port 5000...")
    app.run(port=5000, debug=True)