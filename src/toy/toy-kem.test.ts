import { describe, it, expect } from "vitest";
import { buildToyGoppaCode, encode, pattersonDecode } from "./goppa-code";
import { encapsulate, decapsulate, packBits, randomError } from "./toy-kem";

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("toy McEliece KEM", () => {
  const code = buildToyGoppaCode();

  /**
   * The two exhaustive censuses below are CPU-bound and run past Vitest's 5s
   * default on a shared CI runner (~4x slower than a dev laptop): the 143,360-
   * state census takes ~1.8s locally, so ~7s there. They always did. Vitest 2
   * could not interrupt a synchronous test — the timeout timer is a macrotask
   * and the blocked event loop never reached it — so it silently let them run
   * long; Vitest 4 compares the recorded duration afterwards and fails them.
   * Nothing here got slower (whole-suite test time is 13.75s on Vitest 2 versus
   * 14.12s on Vitest 4 for the same CI runner); the limit simply became real.
   * State it, generously enough to survive a loaded runner and still bounded so
   * a genuine hang fails rather than idles.
   */
  const CENSUS_TIMEOUT_MS = 60_000;

  it("encapsulate → decapsulate yields identical shared secrets", async () => {
    for (let trial = 0; trial < 50; trial += 1) {
      const enc = await encapsulate(code);
      const dec = await decapsulate(code, enc.ciphertext);
      expect(dec.trace.success).toBe(true);
      expect(dec.trace.message).toEqual(enc.message);
      expect(dec.trace.errorPositions).toEqual(enc.errorPositions);
      expect(toHex(dec.sharedSecret)).toBe(toHex(enc.sharedSecret));
      expect(dec.sharedSecret.length).toBe(32);
    }
  });

  it("tampering beyond t errors breaks the shared secret (security boundary)", async () => {
    let mismatches = 0;
    for (let trial = 0; trial < 30; trial += 1) {
      const enc = await encapsulate(code);
      // inject a third error — exceeds the t=2 correction radius
      const tampered = enc.ciphertext.slice();
      const extra = randomError(code.n, 1).indexOf(1);
      tampered[extra] ^= 1;
      const dec = await decapsulate(code, tampered);
      if (toHex(dec.sharedSecret) !== toHex(enc.sharedSecret)) mismatches += 1;
    }
    // exceeding the correction radius must not silently reproduce the secret
    expect(mismatches).toBeGreaterThan(0);
  });

  /**
   * The assertion above ("at least one of thirty random trials differed") is the
   * weakest form of the claim the "Exceed correction radius" control makes, and it
   * was the only thing checking it. The space is small enough for a complete
   * census, so take one: every codeword crossed with every weight-(t+1) error
   * pattern — 143,360 states, exactly the set that control can produce.
   *
   * It also pins the two-way split the UI has to label correctly, and requires
   * both halves to be non-empty so neither branch can quietly stop occurring.
   */
  it("no weight-(t+1) tamper reproduces the sent codeword — complete census", () => {
    const n = code.n;
    const codewords: number[][] = [];
    for (let m = 0; m < 1 << code.k; m += 1) {
      codewords.push(encode(code, Array.from({ length: code.k }, (_, i) => (m >> i) & 1)));
    }
    expect(codewords.length).toBe(1 << code.k);

    let total = 0;
    let undecodable = 0;
    let wrongCodeword = 0;
    let backToOriginal = 0;
    for (const c of codewords) {
      for (let a = 0; a < n; a += 1) {
        for (let b = a + 1; b < n; b += 1) {
          for (let d = b + 1; d < n; d += 1) {
            total += 1;
            const received = c.slice();
            received[a] ^= 1;
            received[b] ^= 1;
            received[d] ^= 1;
            const trace = pattersonDecode(code, received);
            if (!trace.success) undecodable += 1;
            else if (trace.corrected.every((x, i) => x === c[i])) backToOriginal += 1;
            else wrongCodeword += 1;
          }
        }
      }
    }

    expect(total).toBe(codewords.length * ((n * (n - 1) * (n - 2)) / 6));
    // The security boundary, over the whole space rather than a 30-trial sample.
    expect(backToOriginal, "a weight-(t+1) error must never decode back to the sent codeword").toBe(0);
    // Both outcomes the UI must distinguish do occur, so neither label is dead.
    expect(undecodable, "the undecodable branch must be reachable").toBeGreaterThan(0);
    expect(wrongCodeword, "the wrong-codeword branch must be reachable").toBeGreaterThan(0);
    expect(undecodable + wrongCodeword).toBe(total);
  }, CENSUS_TIMEOUT_MS);

  /**
   * The UI's decapsulation error handler used to announce "Undecodable — more
   * than t errors" as the over-radius lesson. It cannot be: g(z) is irreducible,
   * so every non-zero syndrome is invertible mod g and the Euclidean split always
   * terminates. Over a complete census of all 2^n received vectors pattersonDecode
   * throws zero times — the over-radius case returns with success === false.
   */
  it("pattersonDecode never throws — complete census over all 2^n received vectors", () => {
    let threw = 0;
    let failed = 0;
    const total = 1 << code.n;
    for (let r = 0; r < total; r += 1) {
      const received = Array.from({ length: code.n }, (_, i) => (r >> i) & 1);
      try {
        if (!pattersonDecode(code, received).success) failed += 1;
      } catch {
        threw += 1;
      }
    }
    expect(total).toBe(65536);
    expect(threw, "the decoder must signal over-radius by returning, not by throwing").toBe(0);
    expect(failed, "failed decodes must occur, or this census proves nothing").toBeGreaterThan(0);
  }, CENSUS_TIMEOUT_MS);

  it("packBits is LSB-first within each byte", () => {
    expect(Array.from(packBits([1, 0, 1]))).toEqual([0b101]);
    expect(Array.from(packBits([0, 0, 0, 0, 0, 0, 0, 0, 1]))).toEqual([0, 1]);
  });
});
