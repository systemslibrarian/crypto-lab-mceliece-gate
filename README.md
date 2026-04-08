# crypto-lab-mceliece-gate

**Live demo:** [https://systemslibrarian.github.io/crypto-lab-mceliece-gate/](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/)

`Classic McEliece` · `Binary Goppa` · `AES-256-GCM` · `Code-Based`

---

## What It Is

Classic McEliece is a code-based, asymmetric post-quantum key encapsulation mechanism (KEM) first proposed by Robert McEliece in 1978 and standardized by NIST in 2024. It encodes a random error vector into a public-key ciphertext using binary Goppa codes over GF(2^m), and relies on the NP-hardness of syndrome decoding on random binary linear codes as its security foundation. Unlike lattice-based KEMs, its security assumption has resisted all known quantum speedups beyond Grover-like square-root acceleration for over 46 years. The tradeoff is key size: the smallest standard parameter set (mceliece348864) carries a 261,120-byte public key, roughly 220× that of ML-KEM-768.

## When to Use It

- **Long-horizon archival encryption (50-year secrecy horizon):** no sub-exponential quantum attack on syndrome decoding is known, making McEliece the most conservative post-quantum hedge available.
- **High-assurance government or defense systems:** where the cost of cryptographic failure is catastrophic and bandwidth is secondary to confidence in the security assumption.
- **Store-now / decrypt-later threat models:** adversaries recording today's ciphertext traffic to break it with future quantum hardware face no shortcut against McEliece's code-based hardness.
- **Hybrid PQ deployments (code-based + lattice-based):** pairing McEliece with ML-KEM provides defense-in-depth against a break in either assumption class.
- **Not for bandwidth-constrained TLS or IoT:** a 261 KB public key is prohibitive in handshake protocols or constrained devices — use ML-KEM (FIPS 203) instead.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-mceliece-gate/](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/)

The demo walks through the complete Classic McEliece KEM + AES-256-GCM flow in the browser. Users can generate an mceliece348864 keypair, run encapsulation and decapsulation step-by-step, and encrypt and decrypt a plaintext message using the recovered shared secret as an AES-256-GCM key. Additional panels visualize the binary Goppa code structure (generator, scramble, and permutation matrices), a scrollable hex dump of the full 261,120-byte public key, and a side-by-side comparison of Classic McEliece vs ML-KEM-512, BIKE-1, and HQC-128 across key size, ciphertext size, and benchmark cycles.

## What Can Go Wrong

- **Key reuse across encapsulations:** each encapsulation samples a fresh random error vector; reusing a keypair is safe, but implementations that cache or reuse the error vector break IND-CCA2 security immediately.
- **Public key substitution (no binding to identity):** Classic McEliece KEMs do not authenticate the public key — an attacker who can substitute their own key performs a classic MitM. Key infrastructure (certificates, pre-shared fingerprints) must bind the public key to an identity.
- **Parameter set downgrade:** mceliece348864 targets NIST Level 1 (~143-bit classical, ~128-bit quantum). Protocol negotiation that allows fallback to smaller (non-standard) parameters undermines the security claim.
- **Simulation disclosure — this demo is not production McEliece:** the cryptographic operations use pedagogical simulation for browser interactivity; key sizes and security properties are exact per the NIST standard, but the code does not implement the Patterson decoding algorithm or the full NIST KEM API.
- **Memory exposure of a 261 KB private key:** the private key material is large and long-lived; insecure memory handling (logging, serialization to localStorage, XHR transmission) exposes the trapdoor on any system that touches it.

## Real-World Usage

- **NIST FIPS (Classic McEliece standard, 2024):** NIST standardized Classic McEliece as part of its Post-Quantum Cryptography project, recommending it for high-assurance applications where key size is acceptable.
- **PQShield and high-assurance hardware security modules:** PQShield has implemented Classic McEliece in hardware IP targeting long-lifecycle government and defense platforms.
- **PQCRYPTO EU project:** recommended Classic McEliece as the conservative KEM of choice in its 2015 post-quantum migration guidance for high-value data.
- **Open Quantum Safe (liboqs):** the liboqs library ships Classic McEliece reference and optimized implementations used in research, TLS experimentation (via OQS-OpenSSL), and government pilot deployments.
- **German BSI technical guidance (TR-02102-1):** the German Federal Office for Information Security lists Classic McEliece as an approved post-quantum KEM for long-term data protection use cases.

## Related Demos

- [crypto-lab-bike-vault](https://github.com/systemslibrarian/crypto-lab-bike-vault) — BIKE code-based KEM
- [crypto-lab-hqc-vault](https://github.com/systemslibrarian/crypto-lab-hqc-vault) — HQC code-based KEM
- [crypto-lab-kyber-vault](https://github.com/systemslibrarian/crypto-lab-kyber-vault) — ML-KEM / Kyber lattice-based KEM
- [crypto-compare](https://github.com/systemslibrarian/crypto-compare) — Side-by-side KEM comparison dashboard
- [crypto-lab](https://github.com/systemslibrarian/crypto-lab) — Landing page for the full crypto-lab collection

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
