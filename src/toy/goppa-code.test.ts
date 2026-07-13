import { describe, it, expect } from "vitest";
import { add, mul, inv, div, pow, GF_SIZE } from "./gf16";
import {
  polyMul,
  polyMod,
  polyInvMod,
  polyMulMod,
  polySqrtMod,
  polyEval,
  degree
} from "./poly";
import {
  buildToyGoppaCode,
  encode,
  extractMessage,
  binarySyndrome,
  pattersonDecode,
  bruteForceSyndromeDecode,
  scrambleGenerator
} from "./goppa-code";

describe("GF(16) field laws", () => {
  it("addition is XOR and self-inverse", () => {
    for (let a = 0; a < GF_SIZE; a += 1) {
      expect(add(a, a)).toBe(0);
      for (let b = 0; b < GF_SIZE; b += 1) expect(add(a, b)).toBe(a ^ b);
    }
  });

  it("multiplication is commutative with identity 1", () => {
    for (let a = 0; a < GF_SIZE; a += 1) {
      expect(mul(a, 1)).toBe(a);
      expect(mul(a, 0)).toBe(0);
      for (let b = 0; b < GF_SIZE; b += 1) expect(mul(a, b)).toBe(mul(b, a));
    }
  });

  it("every non-zero element has an inverse", () => {
    for (let a = 1; a < GF_SIZE; a += 1) {
      expect(mul(a, inv(a))).toBe(1);
      expect(div(a, a)).toBe(1);
    }
    expect(() => inv(0)).toThrow();
  });

  it("pow agrees with repeated multiplication", () => {
    for (let a = 0; a < GF_SIZE; a += 1) {
      let acc = 1;
      for (let e = 0; e < 8; e += 1) {
        expect(pow(a, e)).toBe(acc);
        acc = mul(acc, a);
      }
    }
  });
});

describe("polynomial arithmetic over GF(16)", () => {
  const g = buildToyGoppaCode().g;

  it("inverse mod g is a true inverse", () => {
    for (let c = 1; c < GF_SIZE; c += 1) {
      const a = [c, 1]; // c + z
      const aInv = polyInvMod(a, g);
      expect(polyMulMod(a, aInv, g)).toEqual([1]);
    }
  });

  it("square root mod g squares back to the original", () => {
    for (let c = 1; c < GF_SIZE; c += 1) {
      const a = polyMod([c, c, 1], g);
      const r = polySqrtMod(a, g);
      expect(polyMulMod(r, r, g)).toEqual(a);
    }
  });

  it("polyMod returns a remainder of lower degree", () => {
    const r = polyMod(polyMul([1, 2, 3], [4, 5]), g);
    expect(degree(r)).toBeLessThan(degree(g));
  });
});

describe("toy Goppa code", () => {
  const code = buildToyGoppaCode();

  it("has the expected shape (n=16, t=2, k=n-mt)", () => {
    expect(code.n).toBe(16);
    expect(code.t).toBe(2);
    expect(code.m).toBe(4);
    expect(code.k).toBe(code.n - code.m * code.t); // 8 when H_bin is full rank
    expect(code.generator.length).toBe(code.k);
  });

  it("every generator row is a genuine codeword (zero syndrome)", () => {
    for (const row of code.generator) {
      expect(binarySyndrome(code, row).every((b) => b === 0)).toBe(true);
    }
  });

  it("encode → extract round-trips the message", () => {
    for (let trial = 0; trial < 64; trial += 1) {
      const msg = Array.from({ length: code.k }, (_, i) => (trial >> i) & 1);
      const cw = encode(code, msg);
      expect(binarySyndrome(code, cw).every((b) => b === 0)).toBe(true);
      expect(extractMessage(code, cw)).toEqual(msg);
    }
  });

  it("Patterson corrects every error pattern of weight ≤ t", () => {
    const msg = Array.from({ length: code.k }, (_, i) => i % 2);
    const codeword = encode(code, msg);
    const n = code.n;

    // weight 0
    expect(pattersonDecode(code, codeword).errorPositions).toEqual([]);

    // weight 1
    for (let i = 0; i < n; i += 1) {
      const r = codeword.slice();
      r[i] ^= 1;
      const trace = pattersonDecode(code, r);
      expect(trace.success).toBe(true);
      expect(trace.errorPositions).toEqual([i]);
      expect(trace.message).toEqual(msg);
    }

    // weight 2 — every pair
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const r = codeword.slice();
        r[i] ^= 1;
        r[j] ^= 1;
        const trace = pattersonDecode(code, r);
        expect(trace.success).toBe(true);
        expect(trace.errorPositions).toEqual([i, j]);
        expect(trace.message).toEqual(msg);
      }
    }
  });

  it("Patterson agrees with the brute-force syndrome oracle", () => {
    const codeword = encode(code, Array.from({ length: code.k }, (_, i) => (i * 3) % 2));
    for (let i = 0; i < code.n; i += 1) {
      for (let j = i + 1; j < code.n; j += 1) {
        const r = codeword.slice();
        r[i] ^= 1;
        r[j] ^= 1;
        const patt = pattersonDecode(code, r).errorPositions;
        const brute = bruteForceSyndromeDecode(code, r)?.errorPositions;
        expect(patt).toEqual(brute);
      }
    }
  });

  it("polyEval finds σ roots exactly at the error positions", () => {
    const codeword = encode(code, new Array(code.k).fill(1));
    const r = codeword.slice();
    r[2] ^= 1;
    r[11] ^= 1;
    const { sigma } = pattersonDecode(code, r);
    expect(polyEval(sigma, code.support[2])).toBe(0);
    expect(polyEval(sigma, code.support[11])).toBe(0);
    expect(polyEval(sigma, code.support[5])).not.toBe(0);
  });
});

describe("public-key scrambling G_pub = S·G·P", () => {
  const code = buildToyGoppaCode();

  it("is deterministic for a fixed seed and shaped k×n", () => {
    const a = scrambleGenerator(code, 123);
    const b = scrambleGenerator(code, 123);
    expect(a.gPub).toEqual(b.gPub);
    expect(a.gPub.length).toBe(code.k);
    expect(a.gPub.every((r) => r.length === code.n)).toBe(true);
  });

  it("uses a genuine permutation P (a bijection on the n columns)", () => {
    const { perm } = scrambleGenerator(code, 7);
    expect([...perm].sort((x, y) => x - y)).toEqual(
      Array.from({ length: code.n }, (_, i) => i)
    );
  });

  it("S is invertible over GF(2) (row space preserved ⇒ same code)", () => {
    // rank(S) === k iff S is invertible; check via RREF pivot count.
    const { S } = scrambleGenerator(code, 42);
    const work = S.map((r) => r.slice());
    let rank = 0;
    for (let col = 0; col < code.k && rank < code.k; col += 1) {
      let piv = -1;
      for (let i = rank; i < code.k; i += 1) if (work[i][col] === 1) { piv = i; break; }
      if (piv === -1) continue;
      [work[rank], work[piv]] = [work[piv], work[rank]];
      for (let i = 0; i < code.k; i += 1) {
        if (i !== rank && work[i][col] === 1) {
          for (let j = 0; j < code.k; j += 1) work[i][j] ^= work[rank][j];
        }
      }
      rank += 1;
    }
    expect(rank).toBe(code.k);
  });

  it("every G_pub row is a codeword of the column-permuted Goppa code", () => {
    // Un-permuting a G_pub row must land back in the null space of H_bin.
    const { gPub, perm } = scrambleGenerator(code, 99);
    for (const row of gPub) {
      const unpermuted = new Array<number>(code.n).fill(0);
      perm.forEach((src, dst) => { unpermuted[src] = row[dst]; });
      expect(binarySyndrome(code, unpermuted).every((b) => b === 0)).toBe(true);
    }
  });
});
