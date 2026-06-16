import { describe, it, expect } from "vitest";
import { buildToyGoppaCode } from "./goppa-code";
import { encapsulate, decapsulate, packBits, randomError } from "./toy-kem";

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("toy McEliece KEM", () => {
  const code = buildToyGoppaCode();

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

  it("packBits is LSB-first within each byte", () => {
    expect(Array.from(packBits([1, 0, 1]))).toEqual([0b101]);
    expect(Array.from(packBits([0, 0, 0, 0, 0, 0, 0, 0, 1]))).toEqual([0, 1]);
  });
});
