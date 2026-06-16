/* ================================================================
   Toy McEliece KEM — ties the real Goppa code into a working
   key-encapsulation flow at a size you can watch end-to-end.

     Encapsulate (Alice):  pick random message m and weight-t error e
                           ciphertext  C = m·G ⊕ e
                           shared key  K = SHA-256(m ‖ e)
     Decapsulate (Bob):    Patterson-decode C → recover (m, e)
                           shared key  K = SHA-256(m ‖ e)

   This mirrors how Classic McEliece derives a session key from a
   decoded error vector — only the parameters are toy-sized.
   ================================================================ */

import {
  type ToyGoppaCode,
  type DecodeTrace,
  encode,
  pattersonDecode
} from "./goppa-code";

export interface ToyEncapsulation {
  message: number[];
  errorVector: number[];
  errorPositions: number[];
  codeword: number[];
  ciphertext: number[];
  sharedSecret: Uint8Array;
}

export interface ToyDecapsulation {
  trace: DecodeTrace;
  sharedSecret: Uint8Array;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Pass the view directly: ArrayBuffer.isView is realm-agnostic, whereas a
  // bare ArrayBuffer fails a cross-realm instanceof check under jsdom.
  const digest = await crypto.subtle.digest("SHA-256", data as unknown as BufferSource);
  return new Uint8Array(digest);
}

/** Pack a bit array (LSB-first within each byte) into bytes. */
export function packBits(bits: number[]): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((bit, i) => {
    if (bit) out[i >> 3] |= 1 << (i & 7);
  });
  return out;
}

function randomMessage(k: number): number[] {
  const bytes = new Uint8Array(Math.ceil(k / 8));
  crypto.getRandomValues(bytes);
  return Array.from({ length: k }, (_, i) => (bytes[i >> 3] >> (i & 7)) & 1);
}

/** Uniformly random weight-t error vector of length n. */
export function randomError(n: number, t: number): number[] {
  const positions = new Set<number>();
  const buf = new Uint32Array(1);
  while (positions.size < t) {
    crypto.getRandomValues(buf);
    positions.add(buf[0] % n);
  }
  const e = new Array<number>(n).fill(0);
  positions.forEach((p) => (e[p] = 1));
  return e;
}

/** Derive the shared secret from the KEM inputs both parties hold. */
async function deriveSecret(message: number[], errorVector: number[]): Promise<Uint8Array> {
  const material = new Uint8Array([...packBits(message), ...packBits(errorVector)]);
  return sha256(material);
}

export async function encapsulate(code: ToyGoppaCode): Promise<ToyEncapsulation> {
  const message = randomMessage(code.k);
  const errorVector = randomError(code.n, code.t);
  const codeword = encode(code, message);
  const ciphertext = codeword.map((bit, i) => bit ^ errorVector[i]);
  const errorPositions = errorVector.flatMap((b, i) => (b ? [i] : []));
  const sharedSecret = await deriveSecret(message, errorVector);
  return { message, errorVector, errorPositions, codeword, ciphertext, sharedSecret };
}

export async function decapsulate(code: ToyGoppaCode, ciphertext: number[]): Promise<ToyDecapsulation> {
  const trace = pattersonDecode(code, ciphertext);
  const sharedSecret = await deriveSecret(trace.message, trace.errorVector);
  return { trace, sharedSecret };
}
