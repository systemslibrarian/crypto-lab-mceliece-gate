export interface KeyComparisonEntry {
  name: string;
  bytes: number;
  note: string;
}

export const MCELIECE_348864_PUBLIC_KEY_BYTES = 261120;

/**
 * McEliece (1978) is the origin of the code-based assumption; Kyber/ML-KEM's
 * Module-LWE line starts with the 2017 NIST submission. The page used to hard-code
 * "46 years" in seven places, which was right when it was written and is wrong now.
 * Derive it so the claim cannot drift away from the calendar again.
 */
export const MCELIECE_ORIGIN_YEAR = 1978;
export const MLKEM_ORIGIN_YEAR = 2017;

export function yearsSince(year: number, now = new Date().getFullYear()): number {
  return now - year;
}

export const MCELIECE_YEARS = yearsSince(MCELIECE_ORIGIN_YEAR);

export const SIZE_COMPARISONS: KeyComparisonEntry[] = [
  { name: "Classic McEliece mceliece348864 public key", bytes: 261120, note: "Classic McEliece submission parameter set (not NIST-standardized)" },
  { name: "ML-KEM-768 public key", bytes: 1184, note: "NIST FIPS 203" },
  { name: "RSA-2048 public key", bytes: 294, note: "DER SubjectPublicKeyInfo typical" },
  { name: "Illustrative webpage payload", bytes: 50000, note: "Fixed 50 KB example, not a web-wide average" },
  { name: "Typical profile photo", bytes: 100000, note: "Compressed JPEG example" }
];

export const KEM_PUBLIC_KEY_BENCHMARKS = [
  { name: "Classic McEliece 348864", bytes: 261120 },
  { name: "ML-KEM-512", bytes: 800 },
  { name: "ML-KEM-768", bytes: 1184 },
  { name: "ML-KEM-1024", bytes: 1568 },
  { name: "BIKE-L1", bytes: 1541 },
  { name: "HQC-128", bytes: 2249 }
];

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (bytes >= 1024) {
    return `${Math.round(bytes / 1024)} KB`;
  }
  return `${bytes} B`;
}

/**
 * Width of a bar, as a percentage, with a 2% floor so a sub-1% value is still
 * visible. This is a DRAWING instruction, not a measurement.
 *
 * It used to be the only number here, and it was also what the bars announced:
 * five of the six KEM bars have true widths between 0.306% and 0.861%, so all
 * five were floored to 2% and every one of them announced "2% of maximum" — a
 * 2.8x spread reported as one identical figure, in the chart whose whole job is
 * relative scale. RSA-2048 (0.113%) was overstated 17.7-fold. Use
 * `percentOfMax()` for anything a reader or a screen reader sees.
 */
export function barWidthPercent(bytes: number, max: number): number {
  return Math.max(2, Math.round((bytes / max) * 100));
}

/** The true proportion, formatted for display. Never floored. */
export function percentOfMax(bytes: number, max: number): string {
  const pct = (bytes / max) * 100;
  if (pct >= 10) return `${Math.round(pct)}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(2)}%`;
}

/** @deprecated width-only; kept as the old name for the bar geometry. */
export const proportion = barWidthPercent;
