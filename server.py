from flask import Flask, request, jsonify
import nacl.signing
import nacl.public
import nacl.encoding
import nacl.secret
import nacl.hash
import nacl.utils
import json
import base64

app = Flask(__name__)

# --- CONFIGURATION ---
# Load Long-Term Server Private Key
with open("server.pri", "rb") as f:
    SERVER_PRI = nacl.signing.SigningKey(f.read(), encoder=nacl.encoding.HexEncoder)

# Load Known Agent Public Key (In a real scenario, this would be a database lookup)
with open("agent.pub", "rb") as f:
    KNOWN_AGENT_PUB_KEY_BYTES = f.read()
    # We load it as a VerifyKey for signature checking
    KNOWN_AGENT_VERIFY_KEY = nacl.signing.VerifyKey(KNOWN_AGENT_PUB_KEY_BYTES, encoder=nacl.encoding.HexEncoder)

# Store session data (In prod, use Redis/DB)
session_store = {}

@app.route('/handshake/init', methods=['POST'])
def init_handshake():
    """ Step 2 & 3: Generate Challenge and send Signed Packet """
    
    # 2. Generate Challenge and Ephemeral Keypair (Curve25519)
    challenge = nacl.utils.random(32)
    server_eph_pri = nacl.public.PrivateKey.generate()
    server_eph_pub = server_eph_pri.public_key

    session_id = base64.b64encode(nacl.utils.random(8)).decode('utf-8')
    
    # Store private parts for later verification
    session_store[session_id] = {
        'challenge': challenge,
        'server_eph_pri': server_eph_pri
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
    data = request.json
    outer_envelope = base64.b64decode(data['outer_envelope'])
    
    try:
        # 11. Verify signature using Agent's Long-term Public Key
        # If verify fails, it raises BadSignatureError
        verified_data_bytes = KNOWN_AGENT_VERIFY_KEY.verify(outer_envelope)
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
        # KDF: Hash the point to get a safe symmetric key (blake2b)
        ecdh_key = nacl.hash.blake2b(shared_point, digest_size=32)

        # 13. Decrypt Inner Box (Crypto-Box)
        # We use SecretBox (Symmetric) because we derived the key manually via ECDH
        box = nacl.secret.SecretBox(ecdh_key)
        encrypted_inner = base64.b64decode(outer_box_content['inner_box'])
        
        decrypted_bytes = box.decrypt(encrypted_inner)
        inner_data = json.loads(decrypted_bytes.decode('utf-8'))

        print(f"\n[SERVER] Decrypted Inner Data: {inner_data}")

        # 14. Verify Agent ID match (Anti-MITM)
        # Compare the ID inside the encrypted box with the one used to verify the outer signature
        agent_pub_inside = inner_data['agent_pub_long_term']
        
        # Convert our known verify key to hex string for comparison
        known_agent_hex = KNOWN_AGENT_VERIFY_KEY.encode(encoder=nacl.encoding.HexEncoder).decode()
        
        if agent_pub_inside != known_agent_hex:
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

        return jsonify({"status": "trusted", "message": "Connection established"})

    except Exception as e:
        print(f"[SERVER] ERROR: {str(e)}")
        return jsonify({"status": "failed", "error": str(e)}), 403

if __name__ == '__main__':
    print("Server running on port 5000...")
    app.run(port=5000, debug=True)