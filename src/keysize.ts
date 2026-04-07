export interface KeyComparisonEntry {
  name: string;
  bytes: number;
  note: string;
}

export const MCELIECE_348864_PUBLIC_KEY_BYTES = 261120;

export const SIZE_COMPARISONS: KeyComparisonEntry[] = [
  { name: "Classic McEliece mceliece348864 public key", bytes: 261120, note: "NIST standardized parameter set" },
  { name: "ML-KEM-768 public key", bytes: 1184, note: "NIST FIPS 203" },
  { name: "RSA-2048 public key", bytes: 294, note: "DER SubjectPublicKeyInfo typical" },
  { name: "Average webpage payload", bytes: 50000, note: "Illustrative modern web median" },
  { name: "Typical profile photo", bytes: 100000, note: "Compressed JPEG example" }
];

export const KEM_PUBLIC_KEY_BENCHMARKS = [
  { name: "Classic McEliece 348864", bytes: 261120 },
  { name: "ML-KEM-512", bytes: 800 },
  { name: "ML-KEM-768", bytes: 1184 },
  { name: "ML-KEM-1024", bytes: 1568 },
  { name: "BIKE-1", bytes: 1541 },
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

export function proportion(bytes: number, max: number): number {
  return Math.max(2, Math.round((bytes / max) * 100));
}
