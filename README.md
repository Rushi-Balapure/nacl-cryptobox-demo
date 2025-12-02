## Single Factor Cryptographic Device Verifier

This document describes the **Single Factor Cryptographic Device Verifier** – a trust-establishment architecture between a device and the server.  
The goal is to use a single factor (cryptographic key material) to strongly verify the device, while protecting against MITM and replay attacks through signed messages, ephemeral keys, and an ECDH-derived symmetric key.

## Steps in Device Trust Connect Architecture

1. Both the Server and the Agent have their own long‑term key pairs.  
	- Let them be:
		- For Server:
			- **server.pri** (private key for the server)
			- **server.pub** (public key for the server)
		- For Agent:
			- *agent.pri* (private key for the agent)
			- *agent.pub* (public key for the agent)
2. Then the device registration happens, where the device details and the *agent.pub* (device public key) are sent to the server and stored in the device registry.
3. The Server generates a cryptographic challenge and a server-ephemeral key pair.  
	- Let them be:
		- **CHALLENGE**
		- **server-ephemeral.pub** (temporary public key for the server)
		- **server-ephemeral.pri** (temporary private key for the server)
4. The Server then sends the **CHALLENGE** and **server-ephemeral.pub**, signed/encrypted using **server.pri**, to the Agent.
5. The Agent receives the box and verifies the signature using **server.pub**. The Agent now has:
	- **CHALLENGE**, and
	- **server-ephemeral.pub**
6. The Agent then generates the agent-ephemeral key pair.  
	- Let them be:
		- *agent-ephemeral.pub* (temporary public key for the agent)
		- *agent-ephemeral.pri* (temporary private key for the agent)
7. The Agent then generates the `ecdhkey` (symmetric key for Crypto-Box encryption) using:
	- `ecdhkey` = ECDH(**server-ephemeral.pub**, *agent-ephemeral.pri*)  
	- ECDH is an asymmetric key agreement algorithm.
8. The Agent solves the **CHALLENGE** to get **CHALLENGE_RESPONSE**.
9. The Agent prepares the inner box (this is the Crypto-Box).  
	- Contents:
		- **CHALLENGE_RESPONSE**
		- Device Identification Attestations (fancy word for device data)
		- *agent.pub*
	- The Agent encrypts this inner box using `ecdhkey`.
10. The Agent then prepares the outer box.  
	- Contents:
		- Inner Box (Crypto-Box)
		- *agent-ephemeral.pub*
	- The Agent signs/encrypts this outer box using *agent.pri*.
11. The outer box is then forwarded to the Server.
12. The Server decrypts/verifies the outer box using *agent.pub*.
13. The Server computes the same `ecdhkey` (the symmetric key used for Crypto-Box encryption):  
	- `ecdhkey` = ECDH(**server-ephemeral.pri**, *agent-ephemeral.pub*)
14. The Server decrypts the inner box (the Crypto-Box) using `ecdhkey`.
15. The Server verifies that the *agent.pub* inside the inner box is the same as the one used to verify the outer box (this step prevents MITM attacks).
16. The Server verifies the **CHALLENGE_RESPONSE** and looks up the device using the Device Identification Attestations.

### Algorithms Used

- Long‑term Ed25519 identity keys on server & device
- Ephemeral X25519 keypairs for each handshake
- ECDH → HKDF → 32‑byte session key
- AEAD (ChaCha20‑Poly1305) for inner/outer encrypted payloads