# Single Factor Cryptographic Device Verifier Architecture

**Version:** 2.0 (NIST SP 800-63-4 Compliant)

This document describes the **Single Factor Cryptographic Device Verifier** – a trust-establishment architecture between a device (Agent) and a Server.

The goal is to use a single factor (cryptographic key material) to strongly verify the device. The architecture protects against Man-in-the-Middle (MITM), spoofing, and replay attacks through a **Shared Secret Binding** process for registration, followed by an authentication handshake using signed messages, ephemeral keys, and ECDH-derived symmetric keys.

## NIST SP 800-63 Revision 4 Compliance

This architecture is designed in accordance with **NIST Special Publication 800-63B-4 (Digital Identity Guidelines: Authentication and Lifecycle Management)**. Specifically, it addresses the following sections:

- **[SP 800-63B-4 Section 6: Authenticator Binding](https://www.google.com/url?sa=E&q=https%3A%2F%2Fpages.nist.gov%2F800-63-4%2Fsp800-63b.html%23binding)**
    
    - Requirement: Binding an authenticator to a subscriber account **SHALL** be performed using a shared secret or trusted channel. We utilize this to prevent the "Trust on First Use" vulnerability.
        
- **[SP 800-63B-4 Section 5.1.3.1: Out-of-Band (OOB) Verifiers](https://www.google.com/url?sa=E&q=https%3A%2F%2Fpages.nist.gov%2F800-63-4%2Fsp800-63b.html%23oob-verifiers)**
    
    - Requirement: Describes the use of a verification code (our REG_TOKEN) displayed on a separate channel to establish trust.
        
- **[SP 800-63B-4 Section 5.2.3: Single-Factor Cryptographic Device](https://www.google.com/url?sa=E&q=https%3A%2F%2Fpages.nist.gov%2F800-63-4%2Fsp800-63b.html%23sfc)**
    
    - Requirement: Governs the use of hardware or software cryptographic modules for authentication.
        

---

## Cryptographic Suite

The following algorithms are used throughout both the Registration and Authentication phases:

- **Identity:** Long‑term **Ed25519** keys (Server & Device).
    
- **Key Exchange:** Ephemeral **X25519** keypairs for each handshake.
    
- **Key Derivation:** **HKDF** (HMAC-based Key Derivation Function) to derive session and binding keys.
    
- **Encryption (AEAD):** **ChaCha20‑Poly1305** for all inner/outer encrypted payloads (provides confidentiality and integrity).
    

---

## Phase I: Secure Device Registration (Authenticator Binding)

This phase replaces the standard "Trust on First Use" (TOFU) model. It establishes the initial trust using a temporary Shared Secret to prevent MITM attacks during key exchange, complying with **NIST SP 800-63B-4 Section 6**.

### Prerequisite: Server Keys

The Server must already possess its long-term identity key pair:

- **server.pri** (Private key)
    
- **server.pub** (Public key)
    

### Step 1: Token Generation (Out-of-Band)

1. **Server** (via Admin Console or User Portal) initiates an "Add New Device" request.
    
2. **Server** generates a high-entropy, short-lived **REG_TOKEN** (e.g., 8f4b-22x9-zp7q).
    
3. **Server** displays this token to the user on a secure screen (Out-of-Band).
    
4. **User** manually enters the REG_TOKEN into the Agent (Device) application.
    
    - Critical: The token is **never** transmitted over the network in plain text.
        

### Step 2: Cryptographic Binding & Key Exchange

1. **Agent** generates its long-term identity key pair:
    
    - **agent.pri** (Private key for the agent)
        
    - **agent.pub** (Public key for the agent)
        
2. **Agent** derives a symmetric encryption key (BindingKey) using the token:
    
    - BindingKey = **HKDF**(Input=REG_TOKEN, Salt="registration_v1", Info="device_binding")
        
3. **Agent** prepares the Registration Payload:
    
    - Payload = { **agent.pub**, Device Identification Attestations (Metadata) }
        
4. **Agent** encrypts the payload using Authenticated Encryption (AEAD):
    
    - Encrypted_Packet = **ChaCha20-Poly1305_Encrypt**(BindingKey, Payload)
        
    - Note: This generates both the Ciphertext and the Poly1305 Authentication Tag.
        
5. **Agent** sends the Encrypted_Packet to the Server.
    

### Step 3: Server Verification & Storage

1. **Server** receives the Encrypted_Packet and retrieves the expected REG_TOKEN.
    
2. **Server** derives the same symmetric key:
    
    - BindingKey = **HKDF**(Input=REG_TOKEN, Salt="registration_v1", Info="device_binding")
        
3. **Server** attempts to decrypt the packet:
    
    - Decrypted_Payload = **ChaCha20-Poly1305_Decrypt**(BindingKey, Encrypted_Packet)
        
4. **Security Check:**
    
    - **If Decryption Fails:** The sender did not possess the REG_TOKEN. The request is **REJECTED** (preventing MITM/Spoofing).
        
    - **If Decryption Succeeds:** The Server confirms the agent.pub is legitimate and securely bound to the user.
        
5. **Server** stores agent.pub and Device Attestations in the Device Registry.
    

---

## Phase II: Device Trust Connect (Authentication Handshake)

Once the device is registered and agent.pub is trusted, the following steps are performed for every authentication session.

### Step 4: Server Challenge Generation

The Server generates a cryptographic challenge and a server-ephemeral key pair.

- Let them be:
    
    - **CHALLENGE**
        
    - **server-ephemeral.pub** (temporary public key for the server)
        
    - **server-ephemeral.pri** (temporary private key for the server)
        

### Step 5: Challenge Delivery

The Server sends the **CHALLENGE** and **server-ephemeral.pub**, signed/encrypted using **server.pri**, to the Agent.

### Step 6: Agent Verification

The Agent receives the box and verifies the signature using **server.pub**. The Agent now has:

- **CHALLENGE**
    
- **server-ephemeral.pub**
    

### Step 7: Agent Ephemeral Key Generation

The Agent generates the agent-ephemeral key pair.

- Let them be:
    
    - **agent-ephemeral.pub** (temporary public key for the agent)
        
    - **agent-ephemeral.pri** (temporary private key for the agent)
        

### Step 8: Session Key Derivation (Agent)

The Agent generates the ecdhkey (symmetric key for Crypto-Box encryption) using:

- ecdhkey = ECDH(**server-ephemeral.pub**, **agent-ephemeral.pri**)
    
- Note: ECDH is an asymmetric key agreement algorithm.
    

### Step 9: Challenge Solution

The Agent solves the **CHALLENGE** to get **CHALLENGE_RESPONSE**.

### Step 10: Inner Box Creation

The Agent prepares the inner box (this is the Crypto-Box).

- Contents:
    
    - **CHALLENGE_RESPONSE**
        
    - Device Identification Attestations
        
    - **agent.pub**
        
- The Agent encrypts this inner box using ecdhkey.
    

### Step 11: Outer Box Creation

The Agent prepares the outer box.

- Contents:
    
    - Inner Box (Crypto-Box)
        
    - **agent-ephemeral.pub**
        
- The Agent signs/encrypts this outer box using **agent.pri**.
    

### Step 12: Submission

The outer box is forwarded to the Server.

### Step 13: Outer Box Decryption

The Server decrypts/verifies the outer box using **agent.pub**.

- Note: Since agent.pub was securely bound in Phase I, the Server trusts this signature.
    

### Step 14: Session Key Derivation (Server)

The Server computes the same ecdhkey (the symmetric key used for Crypto-Box encryption):

- ecdhkey = ECDH(**server-ephemeral.pri**, **agent-ephemeral.pub**)
    

### Step 15: Inner Box Decryption

The Server decrypts the inner box (the Crypto-Box) using ecdhkey.

### Step 16: Binding Verification (Anti-MITM)

The Server verifies that the **agent.pub** inside the inner box is the same as the one used to verify the outer box.

### Step 17: Final Validation

The Server verifies the **CHALLENGE_RESPONSE** and looks up the device using the Device Identification Attestations.

---

## Security Analysis

### 1. Mitigation of Registration MITM (The NIST Fix)

In Phase I, an attacker sitting between the Agent and Server cannot inject their own public key. To create a valid registration packet, one must encrypt the payload using the BindingKey. Deriving this key requires the REG_TOKEN, which is entered manually by the user and never sent over the wire.

### 2. Perfect Forward Secrecy (PFS)

In Phase II, the ecdhkey is derived from ephemeral keys (**server-ephemeral** and **agent-ephemeral**). Even if the long-term identity keys (**server.pri** or **agent.pri**) are compromised in the future, past sessions cannot be decrypted because the ephemeral private keys are discarded after the handshake.

### 3. Replay Protection

- **Registration Phase:** The REG_TOKEN is short-lived and marked as "used" by the server after one successful registration.
    
- **Authentication Phase:** The **CHALLENGE** ensures liveness. An attacker cannot replay an old "Outer Box" because the server will have generated a new Challenge for the current session.
    

### 4. Identity Protection

The device's metadata and agent.pub are always encrypted during transmission (wrapped by BindingKey in Phase I, and ecdhkey in Phase II), ensuring privacy against passive observers.