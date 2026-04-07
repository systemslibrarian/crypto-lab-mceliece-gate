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

export const COMPARISON_ROWS: KEMComparisonRow[] = [
  {
    scheme: "Classic McEliece 348864",
    publicKeyBytes: 261120,
    ciphertextBytes: 128,
    keygenCycles: 6350000,
    encapCycles: 76000,
    decapCycles: 148000,
    securityAssumption: "Syndrome decoding on random linear codes",
    yearsOfCryptanalysis: "46",
    source: "Classic McEliece submission benchmark package (Haswell ref cycles)"
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
    source: "CRYSTALS-Kyber / ML-KEM submission benchmarks (Haswell ref cycles)"
  },
  {
    scheme: "BIKE-1",
    publicKeyBytes: 1541,
    ciphertextBytes: 1573,
    keygenCycles: 4880000,
    encapCycles: 6330000,
    decapCycles: 7810000,
    securityAssumption: "QC-MDPC decoding",
    yearsOfCryptanalysis: "~10",
    source: "BIKE submission benchmark tables (Haswell ref cycles)"
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
    source: "HQC submission benchmark tables (Haswell ref cycles)"
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
