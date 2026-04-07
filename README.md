# crypto-lab-mceliece-gate

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