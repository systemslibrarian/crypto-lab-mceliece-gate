/* ================================================================
   A real (tiny) binary Goppa code — the trapdoor at the heart of
   Classic McEliece, shrunk to GF(16) so every step is visible.

   Construction:
     • field      GF(2^4) = GF(16)
     • support    L = (α_0, …, α_{n-1}), distinct elements of GF(16)
     • Goppa poly g(z), irreducible of degree t  ⇒  g(α_i) ≠ 0 ∀i
     • parity     H[j][i] = α_i^j / g(α_i)      (t × n over GF(16))
                  expanded bitwise to H_bin       (mt × n over GF(2))
     • generator  G = a basis of ker(H_bin)        (k × n over GF(2))

   The legitimate receiver knows (L, g) and decodes t errors in
   polynomial time via Patterson's algorithm. An attacker who sees
   only the scrambled generator faces syndrome decoding of an
   apparently random linear code — the NP-hard problem McEliece
   rests on.
   ================================================================ */

import { GF_M, GF_SIZE, mul, inv, pow } from "./gf16";
import {
  type Poly,
  polyAdd,
  polyEval,
  polyInvMod,
  polySqrtMod,
  pattersonSplit,
  isZero,
  normalize
} from "./poly";

export interface ToyGoppaCode {
  m: number;
  n: number;
  k: number;
  t: number;
  /** support set L (distinct GF(16) elements) */
  support: number[];
  /** Goppa polynomial g(z), little-endian coefficients */
  g: Poly;
  /** t × n parity-check over GF(16) */
  parityGF: number[][];
  /** mt × n parity-check over GF(2) */
  parityBin: number[][];
  /** k × n generator over GF(2) */
  generator: number[][];
  /** the k information-bit column positions (systematic set) */
  infoColumns: number[];
}

/** Find the first irreducible g(z) = z² + z + c (c ≥ 1) over GF(16). */
function findGoppaPolynomial(support: number[]): Poly {
  for (let c = 1; c < GF_SIZE; c += 1) {
    const g: Poly = [c, 1, 1]; // c + z + z²
    const hasRoot = support.some((a) => polyEval(g, a) === 0);
    if (!hasRoot) return g; // irreducible deg-2 ⇒ no root in GF(16)
  }
  throw new Error("no irreducible degree-2 Goppa polynomial found");
}

/** Reduce a binary matrix to RREF in place; return the pivot columns. */
function rref(rows: number[][], nCols: number): number[] {
  const pivots: number[] = [];
  let r = 0;
  for (let col = 0; col < nCols && r < rows.length; col += 1) {
    let pivot = -1;
    for (let i = r; i < rows.length; i += 1) {
      if (rows[i][col] === 1) {
        pivot = i;
        break;
      }
    }
    if (pivot === -1) continue;
    [rows[r], rows[pivot]] = [rows[pivot], rows[r]];
    for (let i = 0; i < rows.length; i += 1) {
      if (i !== r && rows[i][col] === 1) {
        for (let j = 0; j < nCols; j += 1) rows[i][j] ^= rows[r][j];
      }
    }
    pivots.push(col);
    r += 1;
  }
  return pivots;
}

/** Build the toy Goppa code (deterministic: n = 16, t = 2). */
export function buildToyGoppaCode(): ToyGoppaCode {
  const m = GF_M;
  const t = 2;
  const support = Array.from({ length: GF_SIZE }, (_, i) => i); // all of GF(16)
  const n = support.length;
  const g = findGoppaPolynomial(support);

  // Parity check over GF(16): H[j][i] = α_i^j · g(α_i)^{-1}
  const gAtAlpha = support.map((a) => inv(polyEval(g, a)));
  const parityGF: number[][] = [];
  for (let j = 0; j < t; j += 1) {
    parityGF.push(support.map((a, i) => mul(pow(a, j), gAtAlpha[i])));
  }

  // Expand each GF(16) entry to m bits → binary parity check (mt × n).
  const parityBin: number[][] = [];
  for (let j = 0; j < t; j += 1) {
    for (let b = 0; b < m; b += 1) {
      parityBin.push(parityGF[j].map((v) => (v >> b) & 1));
    }
  }

  // Null space of parityBin over GF(2) = the codewords (generator rows).
  const work = parityBin.map((row) => row.slice());
  const pivots = rref(work, n);
  const pivotSet = new Set(pivots);
  const infoColumns = Array.from({ length: n }, (_, i) => i).filter((i) => !pivotSet.has(i));
  const k = infoColumns.length;

  const generator: number[][] = infoColumns.map((free) => {
    const row = new Array<number>(n).fill(0);
    row[free] = 1;
    pivots.forEach((pcol, pi) => {
      row[pcol] = work[pi][free];
    });
    return row;
  });

  return { m, n, k, t, support, g, parityGF, parityBin, generator, infoColumns };
}

/* ================================================================
   Public-key scrambling  G_pub = S · G · P
   The whole reason the McEliece public code "looks random": the
   structured Goppa generator G is mixed by an invertible binary
   S (row operations) and a permutation P (column shuffle). Both are
   real matrices here, computed at toy size so the structure visibly
   dissolves. Bob keeps (S, P, L, g); the attacker sees only G_pub.
   ================================================================ */

export interface ScrambledGenerator {
  /** k×k invertible binary scramble matrix S (row-mixer). */
  S: number[][];
  /** permutation of the n columns (P as a permutation array). */
  perm: number[];
  /** S·G — after row mixing, before the column permutation. */
  mixed: number[][];
  /** G_pub = S·G·P — the public generator an attacker sees. */
  gPub: number[][];
}

/** Multiply two binary matrices over GF(2). */
function binMatMul(a: number[][], b: number[][]): number[][] {
  const rows = a.length;
  const inner = b.length;
  const cols = b[0].length;
  const out: number[][] = [];
  for (let i = 0; i < rows; i += 1) {
    const row = new Array<number>(cols).fill(0);
    for (let kk = 0; kk < inner; kk += 1) {
      if (a[i][kk] === 1) {
        for (let j = 0; j < cols; j += 1) row[j] ^= b[kk][j];
      }
    }
    out.push(row);
  }
  return out;
}

/** A small deterministic PRNG so the scrambled view is stable per load. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Random invertible k×k binary matrix: build as a product of elementary
 *  row operations on the identity, which is invertible by construction. */
function randomInvertibleBinary(k: number, rng: () => number): number[][] {
  const M: number[][] = Array.from({ length: k }, (_, i) =>
    Array.from({ length: k }, (_, j) => (i === j ? 1 : 0))
  );
  // Apply many random row-additions r_i ^= r_j (i≠j); each is invertible.
  const ops = k * k * 3;
  for (let o = 0; o < ops; o += 1) {
    const i = Math.floor(rng() * k);
    let j = Math.floor(rng() * k);
    if (i === j) j = (j + 1) % k;
    for (let c = 0; c < k; c += 1) M[i][c] ^= M[j][c];
  }
  return M;
}

/** Fisher–Yates permutation of [0..n) using the seeded RNG. */
function randomPermutation(n: number, rng: () => number): number[] {
  const p = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i -= 1) {
    const j = Math.floor(rng() * (i + 1));
    [p[i], p[j]] = [p[j], p[i]];
  }
  return p;
}

/**
 * Compute G_pub = S · G · P for the toy code with real, deterministic
 * S (invertible) and P (permutation). This is the actual McEliece
 * public-key construction, performed (not merely described) at a size
 * where the loss of visible structure is watchable.
 */
export function scrambleGenerator(code: ToyGoppaCode, seed = 0x9e3779b9): ScrambledGenerator {
  const rng = mulberry32(seed);
  const S = randomInvertibleBinary(code.k, rng);
  const perm = randomPermutation(code.n, rng);
  const mixed = binMatMul(S, code.generator); // S·G  (k×n)
  const gPub = mixed.map((row) => perm.map((src) => row[src])); // (S·G)·P
  return { S, perm, mixed, gPub };
}

/** Encode a k-bit message into an n-bit codeword: c = message · G. */
export function encode(code: ToyGoppaCode, message: number[]): number[] {
  if (message.length !== code.k) {
    throw new Error(`encode: expected ${code.k}-bit message, got ${message.length}`);
  }
  const c = new Array<number>(code.n).fill(0);
  for (let row = 0; row < code.k; row += 1) {
    if (message[row] === 1) {
      for (let col = 0; col < code.n; col += 1) c[col] ^= code.generator[row][col];
    }
  }
  return c;
}

/** Read the message bits back out of a codeword's information columns. */
export function extractMessage(code: ToyGoppaCode, codeword: number[]): number[] {
  return code.infoColumns.map((col) => codeword[col]);
}

/** Binary syndrome H_bin · vᵀ (length mt). Zero ⇔ v is a codeword. */
export function binarySyndrome(code: ToyGoppaCode, v: number[]): number[] {
  return code.parityBin.map((row) => {
    let s = 0;
    for (let i = 0; i < code.n; i += 1) s ^= row[i] & v[i];
    return s;
  });
}

/** Syndrome polynomial S(z) = Σ_{i: r_i=1} 1/(z − α_i)  mod g(z). */
export function syndromePolynomial(code: ToyGoppaCode, received: number[]): Poly {
  let S: Poly = [0];
  for (let i = 0; i < code.n; i += 1) {
    if (received[i] === 1) {
      const inverse = polyInvMod([code.support[i], 1], code.g); // (z − α_i)^{-1}, −α_i = α_i
      S = polyAdd(S, inverse);
    }
  }
  return normalize(S);
}

export interface DecodeTrace {
  syndrome: Poly;
  T: Poly | null; // S^{-1} mod g
  R: Poly | null; // sqrt(T + z) mod g
  sigma: Poly; // error-locator σ(z)
  errorPositions: number[];
  errorVector: number[];
  corrected: number[];
  message: number[];
  success: boolean;
}

/**
 * Patterson decoding. Returns the recovered error vector plus every
 * intermediate polynomial so the UI can show the trapdoor working.
 */
export function pattersonDecode(code: ToyGoppaCode, received: number[]): DecodeTrace {
  const { g } = code;
  const syndrome = syndromePolynomial(code, received);

  // No syndrome ⇒ already a codeword (zero errors).
  if (isZero(syndrome)) {
    const corrected = received.slice();
    return {
      syndrome,
      T: null,
      R: null,
      sigma: [1],
      errorPositions: [],
      errorVector: new Array<number>(code.n).fill(0),
      corrected,
      message: extractMessage(code, corrected),
      success: binarySyndrome(code, corrected).every((b) => b === 0)
    };
  }

  const T = polyInvMod(syndrome, g); // S^{-1} mod g
  const tau = polyAdd(T, [0, 1]); // T(z) + z
  const R = isZero(tau) ? [0] : polySqrtMod(tau, g); // sqrt(T + z) mod g
  const { alpha, beta } = pattersonSplit(R, g);

  // σ(z) = α(z)² + z · β(z)²
  const sigma = buildLocator(alpha, beta);

  const errorPositions: number[] = [];
  const errorVector = new Array<number>(code.n).fill(0);
  for (let i = 0; i < code.n; i += 1) {
    if (polyEval(sigma, code.support[i]) === 0) {
      errorPositions.push(i);
      errorVector[i] = 1;
    }
  }

  const corrected = received.map((bit, i) => bit ^ errorVector[i]);
  const success = binarySyndrome(code, corrected).every((b) => b === 0);

  return {
    syndrome,
    T,
    R,
    sigma,
    errorPositions,
    errorVector,
    corrected,
    message: extractMessage(code, corrected),
    success
  };
}

/** σ(z) = α(z)² + z·β(z)² — exact polynomial arithmetic (no mod g). */
function buildLocator(alpha: Poly, beta: Poly): Poly {
  const square = (p: Poly): Poly => {
    const out = new Array<number>(p.length * 2 - 1).fill(0);
    for (let i = 0; i < p.length; i += 1) out[2 * i] = mul(p[i], p[i]); // cross terms vanish in char 2
    return out;
  };
  const aSq = square(alpha);
  const bSq = square(beta);
  const zbSq = [0, ...bSq]; // multiply by z
  return normalize(polyAdd(aSq, zbSq));
}

/**
 * Brute-force syndrome decoder — the attacker's view. Tries every
 * error pattern of weight ≤ maxWeight and returns the unique match.
 * Exponential in general; here it doubles as a correctness oracle.
 */
export function bruteForceSyndromeDecode(
  code: ToyGoppaCode,
  received: number[],
  maxWeight = code.t
): { errorPositions: number[]; searchSpace: number } | null {
  const target = binarySyndrome(code, received).join("");
  let searchSpace = 0;
  const positions: number[] = [];

  const dfs = (start: number, weight: number): number[] | null => {
    searchSpace += 1;
    const e = new Array<number>(code.n).fill(0);
    positions.forEach((p) => (e[p] = 1));
    if (binarySyndrome(code, e).join("") === target) return positions.slice();
    if (weight === maxWeight) return null;
    for (let i = start; i < code.n; i += 1) {
      positions.push(i);
      const found = dfs(i + 1, weight + 1);
      if (found) return found;
      positions.pop();
    }
    return null;
  };

  const result = dfs(0, 0);
  return result ? { errorPositions: result, searchSpace } : null;
}

/** Count of error patterns of weight ≤ t over n positions (attacker search size). */
export function syndromeSearchSpace(n: number, t: number): number {
  let total = 0;
  for (let w = 0; w <= t; w += 1) {
    let c = 1;
    for (let i = 0; i < w; i += 1) c = (c * (n - i)) / (i + 1);
    total += c;
  }
  return total;
}
