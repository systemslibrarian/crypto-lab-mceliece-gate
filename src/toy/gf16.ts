/* ================================================================
   GF(2^4) — the finite field GF(16) used by the toy Goppa code.

   Elements are integers 0..15 whose bits are coefficients of a
   polynomial over GF(2): 0b1011 = x^3 + x + 1. Addition is XOR.
   Multiplication is polynomial multiplication reduced modulo the
   primitive polynomial x^4 + x + 1 (0b10011).

   This is *real* field arithmetic — the same operations a production
   Classic McEliece implementation performs over GF(2^12)/GF(2^13),
   just at a size small enough to visualize.
   ================================================================ */

export const GF_M = 4;
export const GF_SIZE = 1 << GF_M; // 16 elements
export const GF_ORDER = GF_SIZE - 1; // 15 non-zero elements
const PRIMITIVE_POLY = 0b10011; // x^4 + x + 1, primitive over GF(2)
const GENERATOR = 0b10; // x is a generator of the multiplicative group

/* exp[i] = generator^i ; log[a] = discrete log of a base the generator. */
const expTable = new Uint8Array(GF_ORDER * 2);
const logTable = new Uint8Array(GF_SIZE);

(function buildTables(): void {
  let x = 1;
  for (let i = 0; i < GF_ORDER; i += 1) {
    expTable[i] = x;
    logTable[x] = i;
    // multiply x by the generator (shift-and-reduce)
    x <<= 1;
    if (x & GF_SIZE) {
      x ^= PRIMITIVE_POLY;
    }
  }
  // duplicate the cycle so exp[i + j] needs no modular reduction for i,j < ORDER
  for (let i = GF_ORDER; i < GF_ORDER * 2; i += 1) {
    expTable[i] = expTable[i - GF_ORDER];
  }
  logTable[0] = 0; // log(0) is undefined; sentinel, never read on the multiply path
})();

void GENERATOR; // documented above; arithmetic uses the precomputed tables

/** Field addition (and subtraction — they coincide in characteristic 2). */
export function add(a: number, b: number): number {
  return a ^ b;
}

/** Field multiplication via log/antilog tables. */
export function mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return expTable[logTable[a] + logTable[b]];
}

/** Multiplicative inverse. Throws on 0, which has no inverse. */
export function inv(a: number): number {
  if (a === 0) throw new Error("GF(16): 0 has no multiplicative inverse");
  return expTable[GF_ORDER - logTable[a]];
}

/** Division a / b. */
export function div(a: number, b: number): number {
  if (b === 0) throw new Error("GF(16): division by zero");
  if (a === 0) return 0;
  return expTable[logTable[a] - logTable[b] + GF_ORDER];
}

/** Exponentiation a^e for e >= 0. */
export function pow(a: number, e: number): number {
  if (e === 0) return 1;
  if (a === 0) return 0;
  let exponent = (logTable[a] * e) % GF_ORDER;
  if (exponent < 0) exponent += GF_ORDER;
  return expTable[exponent];
}

/** Render an element as its hex nibble, e.g. 10 -> "a". */
export function toNibble(a: number): string {
  return (a & 0xf).toString(16);
}
