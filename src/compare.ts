export interface KEMComparisonRow {
  scheme: string;
  publicKeyBytes: number;
  ciphertextBytes: number;
  keygenCycles: number;
  encapCycles: number;
  decapCycles: number;
  securityAssumption: string;
  yearsOfCryptanalysis: string;
  source: string;
}

// Provenance note: the size columns are each scheme's current specification
// figures; the cycle columns are the Round 3 submission reference benchmarks
// (Haswell), which are the last set measured for all four on a common platform.
// The two are labelled separately in the rendered table rather than presented as
// one coherent measurement set.
export const COMPARISON_ROWS: KEMComparisonRow[] = [
  {
    scheme: "Classic McEliece 348864",
    publicKeyBytes: 261120,
    // Round 4 specification (2022-10-23) removed the 32-byte confirmation hash
    // C1 from the ciphertext, taking it from 128 bytes down to 96. Round 3
    // material still quotes 128; every current implementation produces 96.
    ciphertextBytes: 96,
    keygenCycles: 6350000,
    encapCycles: 76000,
    decapCycles: 148000,
    securityAssumption: "Syndrome decoding on random linear codes",
    yearsOfCryptanalysis: "46",
    source: "Sizes: Classic McEliece Round 4 specification (2022-10-23). Cycles: Round 3 submission benchmark package (Haswell ref cycles)"
  },
  {
    scheme: "ML-KEM-512",
    publicKeyBytes: 800,
    ciphertextBytes: 768,
    keygenCycles: 123000,
    encapCycles: 165000,
    decapCycles: 191000,
    securityAssumption: "Module-LWE",
    yearsOfCryptanalysis: "~8",
    source: "Sizes: FIPS 203. Cycles: CRYSTALS-Kyber Round 3 submission benchmarks (Haswell ref cycles)"
  },
  {
    // "BIKE-1" was a Round 1/2 variant name that the team retired; the current
    // convention for the Category 1 parameter set is BIKE-L1 (r = 12323).
    scheme: "BIKE-L1",
    publicKeyBytes: 1541,
    ciphertextBytes: 1573,
    keygenCycles: 4880000,
    encapCycles: 6330000,
    decapCycles: 7810000,
    securityAssumption: "QC-MDPC decoding",
    yearsOfCryptanalysis: "~10",
    source: "Sizes: BIKE Round 4 specification (BIKE-L1). Cycles: BIKE Round 3 submission benchmark tables (Haswell ref cycles)"
  },
  {
    scheme: "HQC-128",
    publicKeyBytes: 2249,
    ciphertextBytes: 4433,
    keygenCycles: 1870000,
    encapCycles: 3010000,
    decapCycles: 3790000,
    securityAssumption: "Quasi-cyclic syndrome decoding (Hamming metric)",
    yearsOfCryptanalysis: "~8",
    source: "Sizes and cycles: HQC Round 3 submission tables (Haswell ref cycles)"
  }
];

export function formatCycles(cycles: number): string {
  if (cycles >= 1_000_000) {
    return `${(cycles / 1_000_000).toFixed(2)} M cycles`;
  }
  if (cycles >= 1_000) {
    return `${(cycles / 1_000).toFixed(0)} K cycles`;
  }
  return `${cycles} cycles`;
}
