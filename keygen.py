import nacl.encoding
import nacl.signing

def generate_identity(name):
    # Generates an Ed25519 Signing Key (Long Term Identity)
    private_key = nacl.signing.SigningKey.generate()
    public_key = private_key.verify_key

    # Save to disk
    with open(f"{name}.pri", "wb") as f:
        f.write(private_key.encode(encoder=nacl.encoding.HexEncoder))
    with open(f"{name}.pub", "wb") as f:
        f.write(public_key.encode(encoder=nacl.encoding.HexEncoder))
    
    print(f"Generated {name} keys.")

if __name__ == "__main__":
    generate_identity("server")
    generate_identity("agent")