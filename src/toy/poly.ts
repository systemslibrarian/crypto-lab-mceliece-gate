/* ================================================================
   Polynomials over GF(16), with arithmetic modulo the Goppa
   polynomial g(z). A polynomial is an array of GF(16) coefficients,
   little-endian by degree: [c0, c1, c2] == c0 + c1·z + c2·z².

   When g(z) is irreducible of degree t, GF(16)[z]/g(z) is the field
   GF(2^(4t)), so every non-zero element has an inverse and a unique
   square root — both of which Patterson's decoder relies on.
   ================================================================ */

import { add, mul, inv } from "./gf16";

export type Poly = number[];

/** Trim trailing zero coefficients so degree() is well defined. */
export function normalize(p: Poly): Poly {
  const out = p.slice();
  while (out.length > 1 && out[out.length - 1] === 0) out.pop();
  return out;
}

/** Degree of p; the zero polynomial has degree -1 by convention. */
export function degree(p: Poly): number {
  const n = normalize(p);
  if (n.length === 1 && n[0] === 0) return -1;
  return n.length - 1;
}

export function isZero(p: Poly): boolean {
  return p.every((c) => c === 0);
}

/** Coefficient-wise addition (== subtraction in characteristic 2). */
export function polyAdd(a: Poly, b: Poly): Poly {
  const len = Math.max(a.length, b.length);
  const out = new Array<number>(len).fill(0);
  for (let i = 0; i < len; i += 1) {
    out[i] = add(a[i] ?? 0, b[i] ?? 0);
  }
  return normalize(out);
}

/** Schoolbook polynomial multiplication over GF(16). */
export function polyMul(a: Poly, b: Poly): Poly {
  if (isZero(a) || isZero(b)) return [0];
  const out = new Array<number>(a.length + b.length - 1).fill(0);
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] === 0) continue;
    for (let j = 0; j < b.length; j += 1) {
      if (b[j] === 0) continue;
      out[i + j] = add(out[i + j], mul(a[i], b[j]));
    }
  }
  return normalize(out);
}

/** Evaluate p at a field element x (Horner's method). */
export function polyEval(p: Poly, x: number): number {
  let acc = 0;
  for (let i = p.length - 1; i >= 0; i -= 1) {
    acc = add(mul(acc, x), p[i]);
  }
  return acc;
}

/** Remainder of a divided by b (b must be non-zero). */
export function polyMod(a: Poly, b: Poly): Poly {
  const divisor = normalize(b);
  if (isZero(divisor)) throw new Error("poly: division by zero polynomial");
  const r = normalize(a).slice();
  const dDeg = degree(divisor);
  const lead = divisor[dDeg];
  const leadInv = inv(lead);
  for (let i = degree(r); i >= dDeg; i = degree(r)) {
    if (r[i] === 0) {
      r.pop();
      continue;
    }
    const factor = mul(r[i], leadInv);
    const shift = i - dDeg;
    for (let j = 0; j <= dDeg; j += 1) {
      r[j + shift] = add(r[j + shift], mul(factor, divisor[j]));
    }
    // r[i] is now zero; trim it
    while (r.length > 1 && r[r.length - 1] === 0) r.pop();
  }
  return normalize(r);
}

/** (a · b) mod g */
export function polyMulMod(a: Poly, b: Poly, g: Poly): Poly {
  return polyMod(polyMul(a, b), g);
}

/** a^e mod g via square-and-multiply. */
export function polyPowMod(a: Poly, e: number, g: Poly): Poly {
  let result: Poly = [1];
  let base = polyMod(a, g);
  let exp = e;
  while (exp > 0) {
    if (exp & 1) result = polyMulMod(result, base, g);
    base = polyMulMod(base, base, g);
    exp >>>= 1;
  }
  return result;
}

/**
 * Inverse of a modulo g, via the extended Euclidean algorithm.
 * Requires gcd(a, g) = 1 (guaranteed when g is irreducible and a != 0).
 */
export function polyInvMod(a: Poly, g: Poly): Poly {
  let [r0, r1] = [normalize(g), polyMod(a, g)];
  let [t0, t1] = [[0] as Poly, [1] as Poly];
  while (!isZero(r1)) {
    const q = polyDivQuotient(r0, r1);
    [r0, r1] = [r1, polyAdd(r0, polyMul(q, r1))];
    [t0, t1] = [t1, polyAdd(t0, polyMul(q, t1))];
  }
  if (degree(r0) !== 0) throw new Error("poly: element is not invertible mod g");
  const scale = inv(r0[0]);
  return normalize(t0.map((c) => mul(c, scale)));
}

/** Quotient of a divided by b. */
function polyDivQuotient(a: Poly, b: Poly): Poly {
  const divisor = normalize(b);
  const r = normalize(a).slice();
  const dDeg = degree(divisor);
  if (dDeg < 0) throw new Error("poly: division by zero polynomial");
  const leadInv = inv(divisor[dDeg]);
  const q = new Array<number>(Math.max(1, degree(r) - dDeg + 1)).fill(0);
  for (let i = degree(r); i >= dDeg; i = degree(r)) {
    if (r[i] === 0) {
      r.pop();
      continue;
    }
    const factor = mul(r[i], leadInv);
    q[i - dDeg] = factor;
    const shift = i - dDeg;
    for (let j = 0; j <= dDeg; j += 1) {
      r[j + shift] = add(r[j + shift], mul(factor, divisor[j]));
    }
    while (r.length > 1 && r[r.length - 1] === 0) r.pop();
  }
  return normalize(q);
}

/**
 * Square root of a modulo an *irreducible* g of degree t.
 * In the field GF(2^(4t)) the squaring map is a bijection, so
 * sqrt(a) = a^(2^(4t-1)).
 */
export function polySqrtMod(a: Poly, g: Poly): Poly {
  const t = degree(g);
  const fieldBits = 4 * t; // GF((2^4)^t) = GF(2^(4t))
  return polyPowMod(a, 2 ** (fieldBits - 1), g);
}

/**
 * Patterson's extended-Euclid split: given R(z) and g(z), find
 * (alpha, beta) with alpha ≡ beta·R (mod g), deg(alpha) ≤ floor(t/2),
 * deg(beta) ≤ floor((t-1)/2). Returns the first remainder whose degree
 * drops to ≤ floor(t/2) together with its R-cofactor.
 */
export function pattersonSplit(R: Poly, g: Poly): { alpha: Poly; beta: Poly } {
  const t = degree(g);
  const stop = Math.floor(t / 2);
  let [r0, r1] = [normalize(g), normalize(R)];
  let [b0, b1] = [[0] as Poly, [1] as Poly];
  while (degree(r1) > stop) {
    const q = polyDivQuotient(r0, r1);
    [r0, r1] = [r1, polyAdd(r0, polyMul(q, r1))];
    [b0, b1] = [b1, polyAdd(b0, polyMul(q, b1))];
  }
  return { alpha: normalize(r1), beta: normalize(b1) };
}
