# crypto-lab-mceliece-gate

`Classic McEliece` · `Binary Goppa` · `AES-256-GCM` · `Code-Based`

## What It Is

Classic McEliece is a code-based, asymmetric post-quantum key encapsulation mechanism (KEM) first proposed by Robert McEliece in 1978. It was a NIST Round 4 candidate; NIST IR 8545 (2025) selected HQC as the code-based KEM and did **not** standardize Classic McEliece, noting it may revisit that decision once the ongoing ISO standardization completes. It uses binary Goppa codes over GF(2^m). Its security depends both on hard generic decoding and on the hidden Goppa structure resisting structural attacks; worst-case NP-hardness for random codes does not establish the security of these specific public keys. The smallest submitted parameter set (mceliece348864) carries a 261,120-byte public key, roughly 220× that of ML-KEM-768.

**Research update (September 25, 2026):** [Weis, ePrint 2026/1984](https://eprint.iacr.org/2026/1984), a preprint building on [Ghoshal, Ishai, Jain and Sun, ePrint 2026/1630](https://eprint.iacr.org/2026/1630) (GIJS), estimates structural key recovery across five Classic McEliece candidate parameter sets at 2^94–2^102 bit operations in a model that does not charge for memory, or 2^110–2^128 with the paper's memory accounting. The estimates use explicit heuristic assumptions. The author recovered a **toy-sized** key; no production-sized key was recovered, and the estimated work remains impractical. This result is independent of the quantum-decoding discussion and does not change NIST's 2025 standardization decision.

## When to Use It

- **Long-horizon archival encryption (50-year secrecy horizon):** a code-based alternative can diversify a hybrid design, but evaluate the new structural estimates and the huge public key before relying on it for long-lived secrets.
- **High-assurance government or defense systems:** where the cost of cryptographic failure is catastrophic and bandwidth is secondary to confidence in the security assumption.
- **Store-now / decrypt-later threat models:** a code-based assumption offers diversity, but long-term planning must account for classical structural research as well as future quantum attacks.
- **Hybrid PQ deployments (code-based + lattice-based):** pairing McEliece with ML-KEM provides defense-in-depth against a break in either assumption class.
- **Not for bandwidth-constrained TLS or IoT:** a 261 KB public key is prohibitive in handshake protocols or constrained devices — use ML-KEM (FIPS 203) instead.
- **Do NOT treat this as production McEliece:** it is a teaching demo running a toy GF(2⁴) Goppa code, not constant-time, and not the full submitted KEM API.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-mceliece-gate](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/)**

A **30-second primer** opens the page, defining the four load-bearing terms in newcomer language — error-correcting code, syndrome, trapdoor, and why decoding a random code is hard — and introducing GF(16)/nibble notation before the first hex appears. The demo then runs a **real binary Goppa code over GF(2⁴)** in the browser — not a hash-based stand-in. Panel 1 also lets you **toggle between the structured generator `G` Bob holds and the scrambled public generator `G_pub = S·G·P`** an attacker sees — both computed live — so you can see how the public key becomes random-looking while keeping in mind that structural attacks can still exploit hidden relations. You can watch a message get encoded, have a weight-`t` error injected (highlighted bit-by-bit), and then see **real Patterson decoding** locate and correct the errors via the live syndrome polynomial `S(z)`, its inverse, the square root, and the error locator `σ(z)` — each step now carries a click-to-expand **"why this step"** annotation explaining what the transform buys you. A "tamper" control adds enough errors to push the current ciphertext past the correction radius and watch decoding fail, and an attacker panel contrasts the trapdoor holder's polynomial-time decode against exponential brute-force syndrome decoding. The recovered shared secret then keys AES-256-GCM end-to-end. Surrounding panels show the submitted parameter sizes (a scrollable hex dump of the 261,120-byte public key), and a side-by-side comparison of Classic McEliece vs ML-KEM-512, BIKE-L1, and HQC-128.

See **[LIMITATIONS.md](LIMITATIONS.md)** for a precise breakdown of what is cryptographically real versus simulated.

## What Can Go Wrong

- **Key reuse across encapsulations:** the KEM permits reuse of a public key, but many sessions under one key can lower the generic multi-instance decoding work factor (see [Syndrome Drain](https://systemslibrarian.github.io/crypto-lab-syndrome-drain/)). Each encapsulation must sample fresh randomness; reusing an error vector can undermine the KEM's security. Rotation limits the multi-instance effect but does not address structural key recovery.
- **Public key substitution (no binding to identity):** Classic McEliece KEMs do not authenticate the public key — an attacker who can substitute their own key performs a classic MitM. Key infrastructure (certificates, pre-shared fingerprints) must bind the public key to an identity.
- **Parameter set downgrade:** mceliece348864 was submitted at NIST Level 1 using the then-known attack estimates. Protocol negotiation that allows fallback to smaller (non-submitted) parameters further undermines security; the 2026 structural estimates also require separate consideration for the submitted sets.
- **Teaching model — this demo is not production McEliece:** the interactive code runs a genuine binary Goppa code with real Patterson decoding, but at toy GF(2⁴) parameters (n=16, k=8, t=2) so it is breakable by hand. It is not constant-time, does not implement the full submitted KEM API (implicit rejection / KDF), and the production-scale key bytes shown in Panel 2 are simulated at the exact specified size. See [LIMITATIONS.md](LIMITATIONS.md).
- **Memory exposure of a 261 KB private key:** the private key material is large and long-lived; insecure memory handling (logging, serialization to localStorage, XHR transmission) exposes the trapdoor on any system that touches it.

## Real-World Usage

- **NIST Round 4 outcome (NIST IR 8545, 2025):** NIST selected HQC as the code-based KEM and did not standardize Classic McEliece, citing its key size and limited adoption interest; it noted Classic McEliece is undergoing ISO standardization and that NIST may consider a standard based on that work later.
- **PQShield and high-assurance hardware security modules:** PQShield has implemented Classic McEliece in hardware IP targeting long-lifecycle government and defense platforms.
- **PQCRYPTO EU project:** recommended Classic McEliece as the conservative KEM of choice in its 2015 post-quantum migration guidance for high-value data.
- **Open Quantum Safe (liboqs):** the liboqs library ships Classic McEliece reference and optimized implementations used in research, TLS experimentation (via OQS-OpenSSL), and government pilot deployments.
- **German BSI technical guidance (TR-02102-1):** the German Federal Office for Information Security lists Classic McEliece as an approved post-quantum KEM for long-term data protection use cases.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mceliece-gate
cd crypto-lab-mceliece-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-bike-vault](https://systemslibrarian.github.io/crypto-lab-bike-vault/) — BIKE QC-MDPC code-based KEM.
- [crypto-lab-hqc-vault](https://systemslibrarian.github.io/crypto-lab-hqc-vault/) — HQC code-based KEM with Reed-Muller/Reed-Solomon decoding.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM / Kyber lattice-based KEM for size comparison.
- [crypto-lab-syndrome-drain](https://systemslibrarian.github.io/crypto-lab-syndrome-drain/) — decoding-failure and DOOM attacks on code-based schemes.
- [crypto-lab-pq-families](https://systemslibrarian.github.io/crypto-lab-pq-families/) — overview of the lattice, code, hash, multivariate, and isogeny PQ families.

## Testing & Accessibility

```bash
npm test         # Vitest: GF(16) laws, exhaustive Patterson decode, KEM round-trip, DOM + XSS
npm run build    # tsc --noEmit && vite build

# Accessibility + responsive audit (requires: npx playwright install chromium)
npm run preview  # in one terminal
npm run a11y     # in another: axe-core WCAG 2.1 AA scan at 320px + desktop, screenshots to .a11y/
```

The `a11y` audit passes with **0 serious/critical WCAG 2.1 AA violations** and **0 horizontal overflow** at a 320px viewport.

The test suite exhaustively verifies that the toy Goppa code corrects **every** error pattern of weight ≤ t at every position, cross-checked against a brute-force syndrome oracle; that the public-key scramble `G_pub = S·G·P` uses a genuinely invertible `S` and a real permutation `P` and that every scrambled row is still a codeword; plus a jsdom integration test that drives the full encapsulate → decapsulate flow and the new primer / scramble-toggle / Patterson-annotation UI. CI runs typecheck + tests before every deploy.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
