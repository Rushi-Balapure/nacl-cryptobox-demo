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
2. The Server generates a cryptographic challenge and a server-ephemeral key pair.  
	- Let them be:
		- **CHALLENGE**
		- **server-ephemeral.pub** (temporary public key for the server)
		- **server-ephemeral.pri** (temporary private key for the server)
3. The Server then sends the **CHALLENGE** and **server-ephemeral.pub**, signed/encrypted using **server.pri**, to the Agent.
4. The Agent receives the box and verifies the signature using **server.pub**. The Agent now has:
	- **CHALLENGE**, and
	- **server-ephemeral.pub**
5. The Agent then generates the agent-ephemeral key pair.  
	- Let them be:
		- *agent-ephemeral.pub* (temporary public key for the agent)
		- *agent-ephemeral.pri* (temporary private key for the agent)
6. The Agent then generates the `ecdhkey` (symmetric key for Crypto-Box encryption) using:
	- `ecdhkey` = ECDH(**server-ephemeral.pub**, *agent-ephemeral.pri*)  
	- ECDH is an asymmetric key agreement algorithm.
7. The Agent solves the **CHALLENGE** to get **CHALLENGE_RESPONSE**.
8. The Agent prepares the inner box (this is the Crypto-Box).  
	- Contents:
		- **CHALLENGE_RESPONSE**
		- Device Identification Attestations (fancy word for device data)
		- *agent.pub*
	- The Agent encrypts this inner box using `ecdhkey`.
9. The Agent then prepares the outer box.  
	- Contents:
		- Inner Box (Crypto-Box)
		- *agent-ephemeral.pub*
	- The Agent signs/encrypts this outer box using *agent.pri*.
10. The outer box is then forwarded to the Server.
11. The Server decrypts/verifies the outer box using *agent.pub*.
12. The Server computes the same `ecdhkey` (the symmetric key used for Crypto-Box encryption):  
	- `ecdhkey` = ECDH(**server-ephemeral.pri**, *agent-ephemeral.pub*)
13. The Server decrypts the inner box (the Crypto-Box) using `ecdhkey`.
14. The Server verifies that the *agent.pub* inside the inner box is the same as the one used to verify the outer box (this step prevents MITM attacks).
15. The Server verifies the **CHALLENGE_RESPONSE** and looks up the device using the Device Identification Attestations.