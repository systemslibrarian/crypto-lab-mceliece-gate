# crypto-lab-mceliece-gate

**Live demo:** [https://systemslibrarian.github.io/crypto-lab-mceliece-gate/](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/)

`Classic McEliece` · `Binary Goppa` · `AES-256-GCM` · `Code-Based`

---

## Overview

**McEliece Gate** is a browser-based interactive demonstration of Classic McEliece — the oldest post-quantum cryptosystem (1978), a NIST PQC standard, and the most conservative post-quantum KEM available. It shows how binary Goppa codes enable post-quantum key encapsulation, why Classic McEliece has enormous public keys, and why that tradeoff is worth it for ultra-high-assurance applications.

## What You Can Explore

1. **Binary Goppa Codes and the McEliece Construction** — How error-correcting codes become a public-key cryptosystem: generator matrix, scramble and permutation matrices, and why the public key looks random.

2. **The Key Size Problem** — Visceral visualization of mceliece348864's 261,120-byte public key vs ML-KEM, RSA, and everyday data objects. Scrollable hex dump of a real generated key.

3. **Encapsulation and Decapsulation** — Step-by-step KEM flow: keypair generation, error-vector sampling, ciphertext creation, shared-secret recovery, and AES-256-GCM message encryption.

4. **Tradeoff Visualization** — Side-by-side comparison of Classic McEliece vs ML-KEM-512 vs BIKE-1 vs HQC-128: key sizes, ciphertext sizes, benchmark cycles, security assumptions, and years of cryptanalysis. Use-case matrix for when McEliece is the right choice.

5. **Why 46 Years Matters** — Timeline from 1978 to 2024 NIST standardization. No quantum speedup beyond Grover, no practical break, and why conservative choice matters for 50-year secrecy.

## Primitives Used

| Primitive | Role |
|---|---|
| **Classic McEliece** (mceliece348864) | Post-quantum KEM — code-based key encapsulation |
| **Binary Goppa Codes** | Algebraic error-correcting codes over GF(2^m) |
| **AES-256-GCM** | Symmetric authenticated encryption (DEM layer) |
| **SHA-256** | Key derivation and hashing |

**Parameter sets (NIST PQC standard):**

| Name | Level | n | k | t | Public key |
|---|---|---|---|---|---|
| mceliece348864 | 1 | 3488 | 2720 | 64 | 261,120 bytes |
| mceliece460896 | 3 | 4608 | 3360 | 96 | 524,160 bytes |
| mceliece6688128 | 5 | 6688 | 5024 | 128 | 1,044,992 bytes |
| mceliece8192128 | 5 alt | 8192 | 6528 | 128 | 1,357,824 bytes |

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mceliece-gate.git
cd crypto-lab-mceliece-gate
npm install
npm run dev
```

Open [http://localhost:5173/crypto-lab-mceliece-gate/](http://localhost:5173/crypto-lab-mceliece-gate/) in your browser.

**Build for production:**

```bash
npm run build
```

**Deploy to GitHub Pages:**

```bash
npm run deploy
```

## Security Notes

- **Classic McEliece is a NIST PQC standard** — recommended for high-assurance long-term encryption where key size is acceptable.
- **Security assumption:** Hardness of syndrome decoding on random binary linear codes (McEliece 1978; Niederreiter 1986).
- **No quantum speedup** beyond square-root (Grover-like) search — unlike lattice problems, no sub-exponential quantum attack is known.
- **This demo uses pedagogical simulation** — parameter sets, key sizes, and security properties are exact per the NIST standard, but the cryptographic operations are illustrative for browser interactivity. This is explicitly disclosed in the UI.
- For bandwidth-constrained deployments (TLS, IoT), use **ML-KEM** (NIST FIPS 203).

## Accessibility

This demo targets **WCAG 2.1 AA** compliance:

- All interactive elements have descriptive ARIA labels
- Full keyboard navigation — logical tab order, no keyboard traps
- Visible focus indicators in both dark and light modes (minimum 3:1 contrast)
- Color-coded indicators always include text equivalents
- `prefers-reduced-motion` respected — animations suppressed
- Minimum contrast: 4.5:1 normal text, 3:1 large text, both modes
- Screen reader navigable with `aria-live` regions for dynamic updates
- Skip-to-content link for keyboard users

## Why This Matters

46 years of unbroken cryptanalysis make Classic McEliece the most conservative post-quantum choice available. The key size is the price of that confidence. When you need to encrypt something that must stay secret for 50 years, McEliece is the most defensible choice in existence.

## Related Demos

- [crypto-lab-bike-vault](https://github.com/systemslibrarian/crypto-lab-bike-vault) — BIKE code-based KEM
- [crypto-lab-hqc-vault](https://github.com/systemslibrarian/crypto-lab-hqc-vault) — HQC code-based KEM
- [crypto-lab-kyber-vault](https://github.com/systemslibrarian/crypto-lab-kyber-vault) — ML-KEM / Kyber lattice-based KEM
- [crypto-compare](https://github.com/systemslibrarian/crypto-compare) — Side-by-side KEM comparison dashboard
- [crypto-lab](https://github.com/systemslibrarian/crypto-lab) — Landing page for the full crypto-lab collection

---

> "So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31

Live demo: https://systemslibrarian.github.io/crypto-lab-mceliece-gate/

Classic McEliece · Binary Goppa · AES-256-GCM · Code-Based

## Overview

crypto-lab-mceliece-gate is a browser-based interactive demo for Classic McEliece, the oldest major post-quantum public-key proposal (1978) and the most conservative post-quantum KEM candidate in long-horizon threat models.

The demo focuses on:

- How binary Goppa code structure enables trapdoor decoding.
- Why Classic McEliece public keys are enormous.
- Why some high-assurance deployments still prefer this tradeoff.

Implementation note: this project discloses an educational simulation layer for browser interactivity.

Illustrative - not production Classic McEliece.

## What You Can Explore

- Panel 1: Binary Goppa code structure and McEliece construction $G_{pub} = S \cdot G_{goppa} \cdot P$.
- Panel 2: Visceral key-size comparisons, including 261,120-byte public key rendering and hex dump preview.
- Panel 3: End-to-end KEM + DEM flow: encapsulation/decapsulation plus AES-256-GCM message encryption.
- Panel 4: Side-by-side tradeoff table across Classic McEliece, ML-KEM, BIKE, and HQC.
- Panel 5: Timeline and cryptanalytic context (1978 to NIST standardization era).

## Primitives Used

- Classic McEliece parameter sets (exact NIST values used in UI copy):
	- mceliece348864: $n=3488$, $k=2720$, $t=64$, public key 261,120 bytes.
	- mceliece460896: $n=4608$, $k=3360$, $t=96$, public key 524,160 bytes.
	- mceliece6688128: $n=6688$, $k=5024$, $t=128$, public key 1,044,992 bytes.
	- mceliece8192128: $n=8192$, $k=6528$, $t=128$, public key 1,357,824 bytes.
- Binary Goppa code toy arithmetic over $GF(2^m)$ for pedagogical visualization.
- WebCrypto AES-256-GCM for symmetric authenticated encryption.

## Running Locally

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

Deploy to GitHub Pages:

```bash
npm run deploy
```

## Security Notes

- Classic McEliece relies on syndrome decoding hardness in random linear codes (McEliece 1978; Niederreiter 1986).
- Known quantum impact is limited to square-root-style search speedups (Grover-like), not a structural break.
- NIST status: Classic McEliece is in NIST PQC standardization track for high-assurance use; ML-KEM is standardized in FIPS 203.
- Recommendation: use Classic McEliece where long-term high assurance outweighs key-size cost; use ML-KEM where bandwidth and key size are tighter constraints.
- This repository is a browser demo and not a production cryptographic library.

## Accessibility

- Target: WCAG 2.1 AA.
- Keyboard navigation across all interactive controls.
- Screen reader support with ARIA labels, live regions for status/error states, and semantic table/section structure.
- Focus-visible styling for both dark and light modes.
- Reduced motion mode via `prefers-reduced-motion`.

## Why This Matters

Classic McEliece has survived decades of cryptanalysis with no practical break, making it one of the most defensible options for 50-year secrecy goals in high-assurance environments.

## Related Demos

- https://github.com/systemslibrarian/crypto-lab-bike-vault
- https://github.com/systemslibrarian/crypto-lab-hqc-vault
- https://github.com/systemslibrarian/crypto-lab-kyber-vault
- https://github.com/systemslibrarian/crypto-compare
- https://github.com/systemslibrarian/crypto-lab

So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31