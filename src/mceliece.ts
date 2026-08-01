export interface McElieceParams {
  name: "mceliece348864" | "mceliece460896" | "mceliece6688128" | "mceliece8192128";
  level: string;
  n: number;
  k: number;
  t: number;
  publicKeyBytes: number;
  ciphertextBytes: number;
}

// Ciphertext sizes are the Round 4 specification values (2022-10-23). Round 4
// removed the 32-byte confirmation hash C1 from the ciphertext, so every set is
// 32 bytes smaller than the Round 3 figure still quoted in older write-ups
// (348864: 128 -> 96, 460896: 188 -> 156, 6688128 / 8192128: 240 -> 208).
export const CLASSIC_MCELIECE_PARAMS: McElieceParams[] = [
  { name: "mceliece348864", level: "Level 1", n: 3488, k: 2720, t: 64, publicKeyBytes: 261120, ciphertextBytes: 96 },
  { name: "mceliece460896", level: "Level 3", n: 4608, k: 3360, t: 96, publicKeyBytes: 524160, ciphertextBytes: 156 },
  { name: "mceliece6688128", level: "Level 5", n: 6688, k: 5024, t: 128, publicKeyBytes: 1044992, ciphertextBytes: 208 },
  { name: "mceliece8192128", level: "Level 5 alt", n: 8192, k: 6528, t: 128, publicKeyBytes: 1357824, ciphertextBytes: 208 }
];

export interface SimulatedKeypair {
  params: McElieceParams;
  publicKey: Uint8Array;
  privateKey: {
    trapdoorSeed: Uint8Array;
    publicKeyDigest: Uint8Array;
    disclosedSimulation: true;
  };
}

export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
  messageMask: Uint8Array;
  errorVectorPositions: number[];
}

const encoder = new TextEncoder();

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function xorBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== right.length) {
    throw new Error(`xorBytes length mismatch: ${left.length} vs ${right.length}`);
  }
  const out = new Uint8Array(left.length);
  for (let i = 0; i < left.length; i += 1) {
    out[i] = left[i] ^ right[i];
  }
  return out;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, item) => acc + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/**
 * Pass the typed-array view straight to WebCrypto. SubtleCrypto accepts
 * any ArrayBufferView, and `ArrayBuffer.isView` is realm-agnostic — a bare
 * ArrayBuffer would fail a cross-realm `instanceof` check (e.g. jsdom's
 * SubtleCrypto against a Node ArrayBuffer).
 */
function toArrayBuffer(data: Uint8Array): BufferSource {
  // Cast needed only because lib.dom's BufferSource pins the backing buffer to
  // ArrayBuffer; the runtime value is a plain ArrayBufferView either way.
  return data as unknown as BufferSource;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(digest);
}

async function expandSeed(seed: Uint8Array, length: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let counter = 0;
  let produced = 0;
  while (produced < length) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const block = await sha256(concatBytes(seed, c));
    chunks.push(block);
    produced += block.length;
    counter += 1;
  }
  return concatBytes(...chunks).slice(0, length);
}

export function toHex(data: Uint8Array, withSpaces = false): string {
  const hex = Array.from(data, (byte) => byte.toString(16).padStart(2, "0"));
  return withSpaces ? hex.join(" ") : hex.join("");
}

function chooseErrorPositions(weight: number, n: number): number[] {
  const selected = new Set<number>();
  const buf = new Uint32Array(1);
  while (selected.size < weight) {
    crypto.getRandomValues(buf);
    selected.add(buf[0] % n);
  }
  return [...selected].sort((a, b) => a - b);
}

export async function generateKeypair(params: McElieceParams): Promise<SimulatedKeypair> {
  const trapdoorSeed = randomBytes(32);
  const publicSeed = await sha256(concatBytes(encoder.encode("classic-mceliece-public"), trapdoorSeed));
  const publicKey = await expandSeed(publicSeed, params.publicKeyBytes);
  const publicKeyDigest = await sha256(publicKey);

  return {
    params,
    publicKey,
    privateKey: {
      trapdoorSeed,
      publicKeyDigest,
      disclosedSimulation: true
    }
  };
}

export async function encapsulate(params: McElieceParams, publicKey: Uint8Array): Promise<EncapsulationResult> {
  const publicKeyDigest = await sha256(publicKey);
  const messageMask = randomBytes(32);
  const errorVectorPositions = chooseErrorPositions(params.t, params.n);
  const errorDigest = await sha256(encoder.encode(errorVectorPositions.join(",")));

  const payload = concatBytes(messageMask, errorDigest);
  const mask = await expandSeed(concatBytes(encoder.encode("enc-mask"), publicKeyDigest), payload.length);
  const maskedPayload = xorBytes(payload, mask);
  const tag = (await sha256(concatBytes(encoder.encode("tag"), payload, publicKeyDigest))).slice(0, 16);

  const ciphertext = new Uint8Array(params.ciphertextBytes);
  ciphertext.set(maskedPayload.slice(0, Math.min(maskedPayload.length, ciphertext.length)), 0);
  if (ciphertext.length > maskedPayload.length) {
    ciphertext.set(tag.slice(0, Math.min(tag.length, ciphertext.length - maskedPayload.length)), maskedPayload.length);
  }

  const sharedSecret = await sha256(concatBytes(encoder.encode("ss"), payload, ciphertext));
  return { ciphertext, sharedSecret, messageMask, errorVectorPositions };
}

export async function decapsulate(keypair: SimulatedKeypair, ciphertext: Uint8Array): Promise<Uint8Array> {
  const payloadLength = 64;
  const mask = await expandSeed(concatBytes(encoder.encode("enc-mask"), keypair.privateKey.publicKeyDigest), payloadLength);
  const maskedPayload = ciphertext.slice(0, payloadLength);
  const payload = xorBytes(maskedPayload, mask);

  const expectedTag = (await sha256(concatBytes(encoder.encode("tag"), payload, keypair.privateKey.publicKeyDigest))).slice(0, 16);
  const actualTag = ciphertext.slice(payloadLength, payloadLength + 16);
  let tagValid = expectedTag.length === actualTag.length;
  for (let i = 0; i < expectedTag.length; i += 1) {
    tagValid = tagValid && expectedTag[i] === actualTag[i];
  }
  if (!tagValid) {
    throw new Error("Ciphertext integrity check failed");
  }

  return sha256(concatBytes(encoder.encode("ss"), payload, ciphertext));
}

export async function deriveAesKey(sharedSecret: Uint8Array): Promise<CryptoKey> {
  const material = await sha256(concatBytes(encoder.encode("aes-256-gcm"), sharedSecret));
  return crypto.subtle.importKey("raw", toArrayBuffer(material), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptMessage(key: CryptoKey, message: string): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = randomBytes(12);
  const plaintext = encoder.encode(message);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext))
  );
  return { iv, ciphertext };
}

export async function decryptMessage(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}
