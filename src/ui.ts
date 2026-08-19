import {
  CLASSIC_MCELIECE_PARAMS,
  deriveAesKey,
  decryptMessage,
  encryptMessage,
  generateKeypair,
  toHex,
  type McElieceParams
} from "./mceliece";
import { COMPARISON_ROWS, cryptanalysisYears, formatCycles } from "./compare";
import {
  KEM_PUBLIC_KEY_BENCHMARKS,
  MCELIECE_348864_PUBLIC_KEY_BYTES,
  MCELIECE_YEARS,
  SIZE_COMPARISONS,
  barWidthPercent,
  formatBytes,
  percentOfMax
} from "./keysize";
import {
  buildToyGoppaCode,
  bruteForceSyndromeDecode,
  syndromeSearchSpace,
  scrambleGenerator,
  type ToyGoppaCode,
  type ScrambledGenerator
} from "./toy/goppa-code";
import { encapsulate, decapsulate, type ToyEncapsulation } from "./toy/toy-kem";
import { toNibble } from "./toy/gf16";
import { polyEval, type Poly } from "./toy/poly";

/* ======================================================================
   Helpers
   ====================================================================== */

function esc(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function schemeTag(name: string): string {
  const lower = name.toLowerCase();
  if (lower.includes("mceliece")) return "mceliece";
  if (lower.includes("ml-kem") || lower.includes("mlkem")) return "mlkem";
  if (lower.includes("bike")) return "bike";
  if (lower.includes("hqc")) return "hqc";
  if (lower.includes("rsa")) return "rsa";
  return "default";
}

/** Render a polynomial over GF(16) as HTML, e.g. z<sup>2</sup> + z + a. */
function polyStr(p: Poly): string {
  const terms: string[] = [];
  for (let i = p.length - 1; i >= 0; i -= 1) {
    const c = p[i];
    if (c === 0) continue;
    if (i === 0) {
      terms.push(toNibble(c));
    } else {
      const z = i === 1 ? "z" : `z<sup>${i}</sup>`;
      terms.push(c === 1 ? z : `${toNibble(c)}${z}`);
    }
  }
  return terms.length ? terms.join(" + ") : "0";
}

/**
 * Bit vector as a row of cells. Exposed to assistive tech as a single
 * image with a concise summary rather than N announced digits.
 */
function renderBitVector(bits: number[], errors: Set<number> = new Set()): string {
  const cells = bits
    .map((b, i) => {
      const flipped = errors.has(i);
      const cls = `bit-cell${b ? " one" : ""}${flipped ? " flipped" : ""}`;
      return `<span class="${cls}" aria-hidden="true">${b}</span>`;
    })
    .join("");
  const errPositions = [...errors].sort((a, b) => a - b);
  const errSummary = errPositions.length ? `, errors at positions ${errPositions.join(", ")}` : "";
  const label = `${bits.length}-bit vector ${bits.join("")}${errSummary}`;
  return `<div class="bit-vector" role="img" aria-label="${label}">${cells}</div>`;
}

/**
 * Editable ciphertext: each bit is a real button so the learner can
 * inject or clear errors. aria-pressed marks bits that differ from the
 * clean codeword (i.e. current errors).
 */
function renderEditableCiphertext(channel: number[], codeword: number[]): string {
  const cells = channel
    .map((b, i) => {
      const isErr = b !== codeword[i];
      const cls = `bit-cell bit-btn${b ? " one" : ""}${isErr ? " flipped" : ""}`;
      return `<button type="button" class="${cls}" data-bit="${i}" aria-pressed="${isErr}" aria-label="ciphertext bit ${i}, value ${b}${isErr ? ", error — activate to clear" : " — activate to flip"}">${b}</button>`;
    })
    .join("");
  return `<div class="bit-vector editable" role="group" aria-label="Ciphertext — activate a bit to add or remove an error">${cells}</div>`;
}

/**
 * One line of the Patterson chain with a plain-language "why this step"
 * that expands on click. The math (the polynomial value) is always shown;
 * the explanation is progressive disclosure so it serves newcomer and
 * cryptographer alike without cluttering the trace.
 */
function renderPattersonStep(
  labelHtml: string,
  valueHtml: string,
  whyShort: string,
  whyLong: string
): string {
  return `
  <div class="pstep">
    <p class="pstep-line"><strong>${labelHtml}</strong> <span class="result-mono">${valueHtml}</span></p>
    <details class="pstep-why">
      <summary><span class="pstep-why-tag">why this step</span> ${whyShort}</summary>
      <p>${whyLong}</p>
    </details>
  </div>`;
}

/**
 * σ(z) evaluated over the whole support set.
 *
 * When decoding succeeded the roots ARE the error positions. When it did not —
 * i.e. the corrected vector is not a codeword, which is the case in every
 * over-radius state — they are merely the roots of a locator that had no valid
 * solution to find, so the column must not assert a bit was flipped there.
 */
function renderSigmaTable(code: ToyGoppaCode, sigma: Poly, decoded: boolean): string {
  const rows = code.support
    .map((a, i) => {
      const v = polyEval(sigma, a);
      const root = v === 0;
      const mark = root ? (decoded ? "✓ error" : "root — not a located error") : "—";
      return `<tr class="${root ? "row-root" : ""}">
        <th scope="row">${i}</th>
        <td>${toNibble(a)}</td>
        <td>${toNibble(v)}</td>
        <td>${mark}</td>
      </tr>`;
    })
    .join("");
  const summary = decoded
    ? "Show σ(z) evaluated over every support element α<sub>i</sub> — this is how the trapdoor locates errors"
    : "Show σ(z) evaluated over every support element α<sub>i</sub> — decoding failed, so these roots do not mark real errors";
  return `
  <details class="sigma-details">
    <summary>${summary}</summary>
    <div class="table-wrap" role="region" aria-label="Error locator evaluated over the support set" tabindex="0">
      <table class="sigma-table">
        <caption class="sr-only">σ(z) evaluated at each support element; zero values mark error positions</caption>
        <thead><tr><th scope="col">i</th><th scope="col">α<sub>i</sub></th><th scope="col">σ(α<sub>i</sub>)</th><th scope="col">root?</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </details>`;
}

/** Large binary matrices are decorative; the card heading describes them. */
function renderBinMatrix(rows: number[][]): string {
  return rows.map((r) => r.join("")).join("\n");
}

function renderGFMatrix(rows: number[][]): string {
  return rows.map((r) => r.map(toNibble).join(" ")).join("\n");
}

function secretHex(secret: Uint8Array, bytes = 8): string {
  return `${toHex(secret.slice(0, bytes))}…`;
}

/* ======================================================================
   HTML builders
   ====================================================================== */

function renderHeader(): string {
  return `
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Classic McEliece</h1>
      <p class="cl-hero-sub">Code-based KEM · Binary Goppa codes</p>
      <p class="cl-hero-desc">Watch a real binary Goppa code encapsulate, break, and Patterson-decode in your browser, alongside the real Classic McEliece key sizes.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Its security has resisted ${MCELIECE_YEARS} years of cryptanalysis with zero practical breaks, making it the most conservative post-quantum KEM for data that must stay secret for decades. The tradeoff is a public key hundreds of times larger than lattice schemes.</p>
    </aside>
  </header>`;
}

function renderChips(): string {
  // `aria-label` is PROHIBITED on an element with no role — a bare <div> maps to
  // `generic`, and the name is silently discarded. axe files that under
  // `incomplete`, never under `violations`, so a violations-only gate reported
  // green while the label did nothing. These chips are a list of peers, so
  // `role="list"` / `role="listitem"` both makes the label legal and gives the
  // reader a count.
  return `
  <div class="primitive-chips" role="list" aria-label="Cryptographic primitives used">
    <span class="chip" role="listitem">Classic McEliece</span>
    <span class="chip" role="listitem">Binary Goppa</span>
    <span class="chip" role="listitem">Patterson decoding</span>
    <span class="chip" role="listitem">AES-256-GCM</span>
    <span class="chip" role="listitem">Code-Based</span>
  </div>`;
}

function renderWhyMatters(): string {
  return `
  <section class="why-matters" aria-label="What is real in this demo">
    <div class="disclosure" role="note">
      <strong>What is real here:</strong> the interactive code in Panel&nbsp;1 and Panel&nbsp;3 is a genuine binary Goppa code over GF(2<sup>4</sup>) with real Patterson decoding — only the parameters are toy-sized so each step is visible. Panel&nbsp;2 uses the exact NIST key sizes (with simulated bytes) to convey real-world scale. This is a teaching model, not a production Classic McEliece implementation — see <a href="https://github.com/systemslibrarian/crypto-lab-mceliece-gate/blob/main/LIMITATIONS.md">LIMITATIONS.md</a>.
    </div>
  </section>`;
}

/**
 * A k×n binary matrix drawn as a grid of on/off cells so a learner can
 * SEE structure (or its loss). Row weights are shown so the eye can track
 * how row-mixing changes each row. Exposed to AT as one summarized image.
 */
function renderMatrixGrid(rows: number[][], label: string): string {
  const cells = rows
    .map(
      (r) =>
        `<div class="mgrid-row">${r
          .map((b) => `<span class="mgrid-cell${b ? " on" : ""}" aria-hidden="true"></span>`)
          .join("")}</div>`
    )
    .join("");
  return `<div class="mgrid" role="img" tabindex="0" aria-label="${esc(label)}">${cells}</div>`;
}

/**
 * S·G·P scrambling, shown for real. Renders the structured generator G that
 * Bob holds and, on toggle, the scrambled public generator G_pub = S·G·P the
 * attacker sees — with the intermediate S·G (row-mixed) available too. Every
 * matrix here is genuinely computed by scrambleGenerator().
 */
function renderScrambleView(code: ToyGoppaCode, sc: ScrambledGenerator): string {
  const onesG = code.generator.reduce((a, r) => a + r.reduce((x, b) => x + b, 0), 0);
  const onesPub = sc.gPub.reduce((a, r) => a + r.reduce((x, b) => x + b, 0), 0);
  return `
  <div class="scramble" id="scramble-view">
    <h3 class="panel-subtitle">Watch the structure dissolve: G<sub>pub</sub> = S · G · P</h3>
    <p>This is the step that makes the public code <em>look random</em>. Bob's structured Goppa generator <strong>G</strong> is multiplied by a random invertible matrix <strong>S</strong> (which mixes the rows) and a permutation <strong>P</strong> (which shuffles the columns). The result <strong>G<sub>pub</sub></strong> spans the exact same code — so Bob can still decode — but its Goppa structure is no longer visible, so an attacker sees only a random-looking linear code. Both matrices below are computed live in your browser.</p>
    <div class="scramble-toggle" role="group" aria-label="Choose which view of the generator to show">
      <button type="button" class="seg-btn is-active" id="scramble-bob" aria-pressed="true">Bob sees: structured G</button>
      <button type="button" class="seg-btn" id="scramble-mixed" aria-pressed="false">Step: S · G (rows mixed)</button>
      <button type="button" class="seg-btn" id="scramble-atk" aria-pressed="false">Attacker sees: G<sub>pub</sub></button>
    </div>
    <div class="scramble-stage">
      <div class="scramble-panel" id="scramble-figure">
        ${renderMatrixGrid(code.generator, `Structured generator G, ${code.k} by ${code.n}, filled cells are ones`)}
      </div>
      <p class="scramble-caption" id="scramble-caption" aria-live="polite">
        <strong>Structured G (${code.k}×${code.n}).</strong> Note the tidy identity block on the left — the systematic structure Bob's trapdoor relies on. Total set bits: ${onesG}.
      </p>
    </div>
    <p class="panel-note">S is invertible, so multiplying by it only re-expresses the same set of codewords; P just relabels bit positions. Nothing is lost — the structure is <em>hidden</em>, not destroyed. That hiding is what forces the attacker into NP-hard syndrome decoding. (Attacker's G<sub>pub</sub> has ${onesPub} set bits — the tidy identity block is gone.)</p>
  </div>`;
}

/* --- 30-second primer (newcomer on-ramp) ---------------------- */

function renderPrimer(): string {
  return `
  <section class="primer" aria-labelledby="primer-title">
    <h2 class="primer-title" id="primer-title">New here? 30-second primer</h2>
    <p class="primer-lede">Four words do all the heavy lifting on this page. If you meet them for the first time here, read this once and the panels below will click.</p>
    <dl class="primer-terms">
      <div class="primer-term">
        <dt>Error-correcting code</dt>
        <dd>A way of adding structured redundancy to data so a few flipped bits can be detected <em>and repaired</em>. A <strong>codeword</strong> is a valid, on-the-grid message; anything a few bits off can be snapped back to the nearest codeword.</dd>
      </div>
      <div class="primer-term">
        <dt>Syndrome</dt>
        <dd>The fingerprint the parity check leaves when bits are wrong. Multiply a received vector by the parity-check matrix <code>H</code>: a clean codeword gives all zeros; errors give a non-zero pattern that <em>depends only on where the errors are</em>. That pattern is the syndrome — the clue you decode from.</dd>
      </div>
      <div class="primer-term">
        <dt>Trapdoor</dt>
        <dd>A computation that is easy one way and hard to reverse — unless you hold a secret. Here the secret is <code>(L, g)</code>: with it, repairing errors is fast; without it, you are stuck brute-forcing.</dd>
      </div>
      <div class="primer-term">
        <dt>Why a random code is hard to decode</dt>
        <dd>Finding the error pattern behind a syndrome, on a code with no visible structure, is <strong>syndrome decoding</strong> — proven NP-hard. McEliece hides the friendly Goppa structure so an attacker sees only a random-looking code and must search.</dd>
      </div>
    </dl>
    <p class="primer-note"><strong>Reading the hex.</strong> The field here is <strong>GF(16)</strong>, so every value is one of 16 elements written as a single hex digit (a <em>nibble</em>): <code>0…9</code> then <code>a…f</code>. When you see <code>a</code> below it means the field element 10, not the letter A.</p>
  </section>`;
}

/* --- Panel 1: Binary Goppa Codes (live) ----------------------- */

function renderPanel1(code: ToyGoppaCode, sc: ScrambledGenerator): string {
  return `
  <section class="panel" id="panel-1" aria-labelledby="p1-title">
    <h2 class="panel-title" id="p1-title">1. Binary Goppa Codes and the McEliece Trapdoor</h2>

    <p><strong>Error-correcting codes</strong> encode data so that even if errors are introduced, the original message can be recovered. Binary Goppa codes are a family of algebraic codes defined over GF(2<sup>m</sup>) by an irreducible Goppa polynomial g(z). Their algebraic structure is the <em>trapdoor</em>: the holder of (L, g) can correct up to <code>t</code> errors in polynomial time; everyone else sees a seemingly random linear code.</p>

    <h3 class="panel-subtitle">The McEliece Construction</h3>
    <p>The public key is formed as <code>G<sub>pub</sub> = S &middot; G<sub>goppa</sub> &middot; P</code>. The scramble matrix <strong>S</strong> and permutation matrix <strong>P</strong> hide the structured Goppa generator so the public code looks random. An attacker who sees only G<sub>pub</sub> faces decoding a random linear code — <strong>syndrome decoding</strong>, known to be NP-hard (Berlekamp, McEliece &amp; van Tilborg 1978). The best known attacks (information-set decoding) remain exponential.</p>

    <div class="callout">${MCELIECE_YEARS} years without a practical break — the most battle-tested post-quantum proposal in existence.</div>

    <h3 class="panel-subtitle">This Page's Live Toy Code — GF(2<sup>4</sup>), n=${code.n}, k=${code.k}, t=${code.t}</h3>
    <p class="panel-note">Everything below is computed in your browser by the same code that powers Panel&nbsp;3. Real Classic McEliece uses GF(2<sup>12</sup>)/GF(2<sup>13</sup>) with thousands of columns; the structure is identical.</p>

    <div class="param-grid">
      <div class="param-item"><span class="param-key">Field</span><span class="param-val">GF(2<sup>4</sup>) = GF(16), prim. poly z<sup>4</sup>+z+1</span></div>
      <div class="param-item"><span class="param-key">Support set L</span><span class="param-val mono">[${code.support.map(toNibble).join(", ")}]</span></div>
      <div class="param-item"><span class="param-key">Goppa poly g(z)</span><span class="param-val mono">${polyStr(code.g)}</span></div>
      <div class="param-item"><span class="param-key">Corrects</span><span class="param-val">t = ${code.t} errors (min. distance ≥ ${2 * code.t + 1})</span></div>
    </div>

    <div class="matrix-grid" role="list" aria-label="Live matrices of the toy Goppa code">
      <div class="matrix-card" role="listitem">
        <h4>Parity-check H over GF(16) — ${code.t}×${code.n}</h4>
        <pre aria-hidden="true">${renderGFMatrix(code.parityGF)}</pre>
      </div>
      <div class="matrix-card" role="listitem">
        <h4>Binary H — ${code.parityBin.length}×${code.n}</h4>
        <pre aria-hidden="true">${renderBinMatrix(code.parityBin)}</pre>
      </div>
      <div class="matrix-card" role="listitem">
        <h4>Generator G — ${code.k}×${code.n}</h4>
        <pre aria-hidden="true">${renderBinMatrix(code.generator)}</pre>
      </div>
    </div>
    <p class="panel-note">H is shown as hex nibbles (each GF(16) element is 4 bits). Each generator row is a codeword: <code>H&middot;G<sup>T</sup> = 0</code>. The public key in real McEliece is a scrambled version of <strong>G</strong>; the private key is <strong>(L, g)</strong>.</p>

    ${renderScrambleView(code, sc)}
  </section>`;
}

/* --- Panel 2: Key Size Problem -------------------------------- */

function renderSizeCards(): string {
  const max = Math.max(...SIZE_COMPARISONS.map((e) => e.bytes));
  return SIZE_COMPARISONS.map((e) => {
    // Width is floored at 2% so a sub-1% bar stays visible; the LABEL must still
    // be the real proportion. Announcing the floor turned RSA-2048's 0.11% into
    // "2%" and made five of the six KEM bars below claim the same size.
    const width = barWidthPercent(e.bytes, max);
    const pct = percentOfMax(e.bytes, max);
    return `
    <div class="size-card" role="listitem">
      <h4>${esc(e.name)}</h4>
      <span class="size-card-value">${e.bytes.toLocaleString()} bytes (${formatBytes(e.bytes)}) · ${pct} of the largest</span>
      <div class="meter" role="img" aria-label="Relative size: ${pct} of the largest key shown">
        <span class="meter-fill" style="width:${width}%"></span>
      </div>
      <span class="size-card-note">${esc(e.note)}</span>
    </div>`;
  }).join("");
}

function renderKemBars(): string {
  const max = Math.max(...KEM_PUBLIC_KEY_BENCHMARKS.map((k) => k.bytes));
  return KEM_PUBLIC_KEY_BENCHMARKS.map((k) => {
    const width = barWidthPercent(k.bytes, max);
    const pct = percentOfMax(k.bytes, max);
    const tag = schemeTag(k.name);
    const floored = width !== Math.round((k.bytes / max) * 100);
    return `
    <li class="bar-item" aria-label="${esc(k.name)}: ${formatBytes(k.bytes)}">
      <div class="bar-label">
        <span>${esc(k.name)}</span>
        <span class="bar-value">${formatBytes(k.bytes)} · ${pct}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" data-scheme="${tag}" style="width:${width}%" role="img" aria-label="${pct} of the largest key shown${floored ? ", drawn at the 2 percent minimum bar width" : ""}"></div>
      </div>
    </li>`;
  }).join("");
}

function renderPanel2(): string {
  const mcelieceBytes = MCELIECE_348864_PUBLIC_KEY_BYTES;
  const mlKemBytes = KEM_PUBLIC_KEY_BENCHMARKS.find((entry) => entry.name === "ML-KEM-768")!.bytes;
  const rsaBytes = SIZE_COMPARISONS.find((entry) => entry.name === "RSA-2048 public key")!.bytes;
  const photoBytes = SIZE_COMPARISONS.find((entry) => entry.name === "Typical profile photo")!.bytes;
  return `
  <section class="panel" id="panel-2" aria-labelledby="p2-title">
    <h2 class="panel-title" id="p2-title">2. The Key Size Problem (Real Parameters)</h2>

    <p>The smallest Classic McEliece parameter set — <strong>mceliece348864</strong> (NIST Level 1) — has a <strong>261,120-byte</strong> public key — ${formatBytes(mcelieceBytes)} for one public key.</p>

    <h3 class="panel-subtitle">How Big Is ${formatBytes(mcelieceBytes)}?</h3>
    <div class="size-grid" role="list" aria-label="Public key size comparisons">
      ${renderSizeCards()}
    </div>

    <p>One McEliece public key equals <strong>~${Math.round(mcelieceBytes / mlKemBytes)}</strong> ML-KEM-768 keys or <strong>~${Math.round(mcelieceBytes / rsaBytes)}</strong> RSA-2048 keys. It is about <strong>${(mcelieceBytes / photoBytes).toFixed(1)} times</strong> the fixed 100 KB profile-photo example above.</p>

    <h3 class="panel-subtitle">All NIST PQ KEMs by Public Key Size</h3>
    <ul class="bar-chart" aria-label="Public key size comparison bar chart">
      ${renderKemBars()}
    </ul>
    <p class="panel-note">Every scheme except McEliece is under 1% of the largest bar, so those bars are drawn at a 2% minimum width to stay visible. The percentage beside each label is the real one — read those, not the bar lengths, when comparing the small schemes with one another.</p>

    <h3 class="panel-subtitle">Public Key Hex Dump</h3>
    <p>A live hex dump of the first 8 KB of a generated mceliece348864 public key — simulated bytes at the exact size the Classic McEliece specification defines. (Specified, not standardized: NIST did not standardize Classic McEliece — see the 2025 entry in Panel&nbsp;5.) Scroll to feel the scale.</p>
    <label for="pk-hex" class="sr-only">Public key hex dump (first 8192 bytes)</label>
    <textarea id="pk-hex" class="hex-dump" readonly aria-label="Public key hex dump, first 8192 bytes">Generating…</textarea>

    <div class="callout">This is the price of ${MCELIECE_YEARS} years of cryptanalysis confidence.</div>
  </section>`;
}

/* --- Panel 3: The toy KEM, working ---------------------------- */

function renderPanel3(code: ToyGoppaCode): string {
  return `
  <section class="panel" id="panel-3" aria-labelledby="p3-title">
    <h2 class="panel-title" id="p3-title">3. Encapsulation &amp; Decapsulation (Live Toy KEM)</h2>

    <p>This runs the <strong>real Goppa code from Panel&nbsp;1</strong> as a key-encapsulation mechanism. Alice picks a random message <code>m</code> and a weight-${code.t} error <code>e</code>, sends <code>C = m·G ⊕ e</code>, and the shared secret is <code>SHA-256(m ‖ e)</code>. Bob's trapdoor (L, g) lets him Patterson-decode <code>C</code> and recover the same secret in a handful of field operations. An attacker without it has to search — which at these toy parameters step&nbsp;3 below does successfully, in 137 patterns. The security claim is about cost, not impossibility: at real parameters that same search is out of reach.</p>

    <div id="aria-live-status" class="aria-status" role="status" aria-live="polite"></div>
    <div id="error-status" class="error-status" role="alert" aria-live="assertive"></div>

    <!-- Step 1: Encapsulation -->
    <div class="step" id="step-encap">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">1</span>
        <span class="step-title">Encapsulation (Alice)</span>
      </div>
      <p>Sample a random ${code.k}-bit message and a weight-${code.t} error vector, then form the ciphertext <code>C = m·G ⊕ e</code>. After encapsulating you can <strong>tap any ciphertext bit</strong> to inject or clear errors yourself and watch how decoding responds.</p>
      <div class="btn-row">
        <button id="btn-encap" class="btn btn-primary" type="button" aria-label="Run encapsulation">Encapsulate</button>
        <button id="btn-tamper" class="btn btn-secondary" type="button" disabled aria-label="Raise the error weight beyond the correction radius">Exceed correction radius</button>
      </div>
      <div id="out-encap" class="output-area" role="status" aria-live="polite" aria-label="Encapsulation output"></div>
    </div>

    <!-- Step 2: Decapsulation -->
    <div class="step" id="step-decap">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">2</span>
        <span class="step-title">Decapsulation (Bob — has the trapdoor)</span>
      </div>
      <p>Patterson's algorithm: build syndrome S(z), invert it, take a square root, split via the extended Euclidean algorithm, and form the error locator σ(z). Its roots are the error positions.</p>
      <div class="btn-row">
        <button id="btn-decap" class="btn btn-primary" type="button" disabled aria-label="Run Patterson decapsulation">Decapsulate</button>
      </div>
      <div id="out-decap" class="output-area" role="status" aria-live="polite" aria-label="Decapsulation output"></div>
    </div>

    <!-- Step 3: Attacker view -->
    <div class="step" id="step-attack">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">3</span>
        <span class="step-title">Attacker (no trapdoor)</span>
      </div>
      <p>Without (L, g), the attacker must solve syndrome decoding on a code that looks random — searching error patterns by brute force. Feasible at toy size; exponential at real parameters.</p>
      <div class="btn-row">
        <button id="btn-attack" class="btn btn-secondary" type="button" disabled aria-label="Run brute-force syndrome decoding">Run brute-force attack</button>
      </div>
      <div id="out-attack" class="output-area" role="status" aria-live="polite" aria-label="Attacker output"></div>
    </div>

    <!-- Step 4: AES-256-GCM -->
    <div class="step" id="step-aes">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">4</span>
        <span class="step-title">AES-256-GCM Wrap (KEM + DEM)</span>
      </div>
      <p>The recovered shared secret keys AES-256-GCM to encrypt and decrypt a message end-to-end.</p>
      <div class="input-group">
        <label for="aes-message">Message to encrypt</label>
        <textarea id="aes-message" rows="2">Classic McEliece: conservative post-quantum security since 1978.</textarea>
      </div>
      <div class="btn-row">
        <button id="btn-encrypt" class="btn btn-primary" type="button" disabled aria-label="Encrypt message with AES-256-GCM">Encrypt</button>
        <button id="btn-decrypt" class="btn btn-secondary" type="button" disabled aria-label="Decrypt ciphertext">Decrypt</button>
      </div>
      <div id="out-aes" class="output-area" role="status" aria-live="polite" aria-label="AES encryption and decryption output"></div>
    </div>
  </section>`;
}

/* --- Panel 4: Tradeoff Visualization -------------------------- */

function renderComparisonRows(): string {
  return COMPARISON_ROWS.map((r) => {
    const isHighlight = r.scheme.toLowerCase().includes("mceliece");
    return `
    <tr${isHighlight ? ' class="row-highlight"' : ""}>
      <th scope="row">${esc(r.scheme)}</th>
      <td>${formatBytes(r.publicKeyBytes)}</td>
      <td>${formatBytes(r.ciphertextBytes)}</td>
      <td>${formatCycles(r.keygenCycles)}</td>
      <td>${formatCycles(r.encapCycles)}</td>
      <td>${formatCycles(r.decapCycles)}</td>
      <td>${esc(r.securityAssumption)}</td>
      <td>${cryptanalysisYears(r)}</td>
    </tr>`;
  }).join("");
}

function renderUseCases(): string {
  const cases = [
    { title: "Long-term archival encryption", desc: "Data that must remain secret for 50+ years. Key size is irrelevant if stored once.", rec: "strong", recLabel: "McEliece: strong choice" },
    { title: "Government / military high-assurance", desc: "Maximum cryptanalytic confidence required. Conservative assumptions outweigh bandwidth cost.", rec: "strong", recLabel: "McEliece: strong choice" },
    { title: "Hybrid PQ where key size is acceptable", desc: "Combined classical + PQ deployment. McEliece adds a code-based assumption alongside lattice-based.", rec: "moderate", recLabel: "McEliece: viable" },
    { title: "Store now, decrypt later threat model", desc: "Adversary records today, breaks crypto later. McEliece offers the strongest hedge against future cryptanalysis.", rec: "strong", recLabel: "McEliece: strong choice" },
    { title: "General TLS / web traffic", desc: "Latency and bandwidth constrained. ML-KEM is the practical choice here.", rec: "weak", recLabel: "McEliece: poor fit — use ML-KEM" },
    { title: "IoT / constrained devices", desc: "Memory and bandwidth extremely limited. McEliece key sizes are prohibitive.", rec: "weak", recLabel: "McEliece: poor fit — use ML-KEM" }
  ];
  return cases.map((c) => `
    <div class="use-case-card" role="listitem">
      <h4>${esc(c.title)}</h4>
      <p>${esc(c.desc)}</p>
      <span class="recommend-tag ${c.rec}">${esc(c.recLabel)}</span>
    </div>`).join("");
}

function renderPanel4(): string {
  return `
  <section class="panel" id="panel-4" aria-labelledby="p4-title">
    <h2 class="panel-title" id="p4-title">4. The Tradeoff Visualization</h2>

    <p>Classic McEliece has the <strong>smallest ciphertext</strong> of any code-based KEM but the <strong>largest public key</strong> by orders of magnitude.</p>

    <p><strong>Where these numbers come from.</strong> The two kinds of column have different provenance and are labelled separately rather than presented as one measurement set. <em>Sizes</em> are specification figures — for Classic McEliece these are the Round 4 values (specification of 23 October 2022), in which the 32-byte confirmation hash was dropped from the ciphertext and it fell from 128 bytes to 96; older Round 3 write-ups still quote 128. <em>Cycle counts</em> are the Round 3 submission reference benchmarks on Haswell, the last set measured for all four schemes on a common platform; the Round 4 ciphertext change does not meaningfully move them.</p>

    <div class="table-wrap" role="region" aria-label="KEM comparison table" tabindex="0">
      <table class="comparison-table">
        <caption class="sr-only">mceliece348864 vs ML-KEM-512 vs BIKE-L1 vs HQC-128</caption>
        <thead>
          <tr>
            <th scope="col">Scheme</th>
            <th scope="col">Public key</th>
            <th scope="col">Ciphertext</th>
            <th scope="col">Keygen</th>
            <th scope="col">Encap</th>
            <th scope="col">Decap</th>
            <th scope="col">Security assumption</th>
            <th scope="col">Cryptanalysis</th>
          </tr>
        </thead>
        <tbody>
          ${renderComparisonRows()}
        </tbody>
      </table>
    </div>

    <div class="callout"><strong>Key insight:</strong> McEliece has the smallest ciphertext among major code-based contenders but by far the largest public key. The "years of cryptanalysis" column tells the story — ${MCELIECE_YEARS} years vs ${cryptanalysisYears(COMPARISON_ROWS.find((r) => r.scheme === "ML-KEM-512")!)} for lattice-based alternatives.</div>

    <h3 class="panel-subtitle">When Is McEliece Worth the Key Size?</h3>
    <div class="use-case-grid" role="list" aria-label="Use case matrix">
      ${renderUseCases()}
    </div>
  </section>`;
}

/* --- Panel 5: Why 46 Years Matters ---------------------------- */

function renderPanel5(): string {
  const events = [
    { year: "1978", text: "Robert McEliece proposes a code-based public-key cryptosystem using binary Goppa codes. First practical code-based encryption." },
    { year: "1986", text: "Harald Niederreiter publishes the dual formulation via syndrome decoding, establishing the twin pillars of code-based crypto." },
    { year: "1988", text: "Sidelnikov-Shestakov attack breaks Reed-Solomon McEliece but Goppa codes remain secure — structural choice validated." },
    { year: "2008", text: "Bernstein, Lange, Peters improve information-set decoding. Best attacks remain exponential. Parameters adjusted, scheme unbroken." },
    { year: "2017", text: "Classic McEliece submitted to NIST PQC competition. Advances through Round 1, 2, 3, and 4." },
    { year: "2022", text: "NIST selects ML-KEM (Kyber) for primary standardization. Classic McEliece continues as Round 4 candidate for high-assurance use." },
    { year: "2025", text: "NIST closes Round 4 (NIST IR 8545): HQC is selected as the code-based KEM and Classic McEliece is NOT standardized — NIST may revisit it once ISO standardization completes. 46+ years of cryptanalysis, zero practical breaks." }
  ];

  const timeline = events.map((e) => `
    <li class="timeline-item">
      <span class="timeline-year">${e.year}</span>
      <span class="timeline-text">${esc(e.text)}</span>
    </li>`).join("");

  return `
  <section class="panel" id="panel-5" aria-labelledby="p5-title">
    <h2 class="panel-title" id="p5-title">5. Why ${MCELIECE_YEARS} Years Matters</h2>

    <ul class="timeline" aria-label="Classic McEliece cryptanalysis timeline">
      ${timeline}
    </ul>

    <h3 class="panel-subtitle">No Quantum Shortcut</h3>
    <p>No known quantum speedup is better than square-root search acceleration (Grover-like). Unlike lattice problems, where sub-exponential quantum attacks remain an active area of research, syndrome decoding on random linear codes has no known path to polynomial quantum speedup.</p>

    <h3 class="panel-subtitle">The Conservative Choice</h3>
    <p>Lattice cryptanalysis is younger and still in motion, but it is worth being exact about what has actually moved. The subfield and "overstretched" NTRU attacks (Albrecht&ndash;Bai&ndash;Ducas, CRYPTO 2016; Kirchner&ndash;Fouque, EUROCRYPT 2017) break NTRU instances whose modulus is very large relative to the dimension &mdash; the regime used by some FHE and graded-encoding constructions. They do <strong>not</strong> apply to ML-KEM's Module-LWE parameters, and citing them as progress against Kyber would be a category error.</p>

    <p>What has genuinely moved is the <em>estimate</em>. Improved dual-attack analyses (Guo&ndash;Johansson, ASIACRYPT 2021; MATZOV, 2022) shaved bits off the published Kyber security figures; Ducas&ndash;Pulles (CRYPTO 2023) then argued that those analyses rest on heuristics that do not hold, restoring the primal attack as the best-understood line of attack. ML-KEM has not been broken and nothing has invalidated its parameters. The honest statement is narrower than "significant cryptanalytic progress": roughly a decade in, the community is still arguing over how to <em>price</em> the best known attack, within a few bits. Classic McEliece's assumption has been under attack since 1978 and the best attacks are still exponential information-set decoding, so its cost estimate has had far longer to settle. If you need something to stay secret for 50 years, that settledness &mdash; not a claim that lattices are falling &mdash; is the argument for McEliece.</p>

    <p>Classic McEliece appears in government and defense research contexts where the cost of being wrong is catastrophic and key size is an acceptable tradeoff.</p>

    <div class="callout"><strong>References:</strong> McEliece (1978), Niederreiter (1986), Bernstein-Lange-Peters (2008), NIST IR 8545 (Round 4 status report, 2025), Classic McEliece submission (classic.mceliece.org).</div>
  </section>`;
}

/* --- Cross Links & Footer ------------------------------------- */

function renderCrossLinks(): string {
  const links = [
    { href: "https://systemslibrarian.github.io/crypto-lab-bike-vault/", label: "crypto-lab-bike-vault" },
    { href: "https://systemslibrarian.github.io/crypto-lab-hqc-vault/", label: "crypto-lab-hqc-vault" },
    { href: "https://systemslibrarian.github.io/crypto-lab-kyber-vault/", label: "crypto-lab-kyber-vault" },
    { href: "https://systemslibrarian.github.io/crypto-compare/", label: "crypto-compare (KEM category)" }
  ];
  const badges = links.map((l) =>
    `<a href="${l.href}" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open ${l.label}">${esc(l.label)}</a>`
  ).join("");

  return `
  <nav class="cross-links" aria-label="Related demos">
    <h2>Related Demos</h2>
    <div class="badge-grid">${badges}</div>
  </nav>`;
}

function renderFooter(): string {
  return `
  <footer class="demo-footer" aria-label="Footer">
    <p class="footer-related">Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open crypto-lab-bike-vault">crypto-lab-bike-vault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open crypto-lab-hqc-vault">crypto-lab-hqc-vault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open crypto-lab-kyber-vault">crypto-lab-kyber-vault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-syndrome-drain/" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open crypto-lab-syndrome-drain">crypto-lab-syndrome-drain</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-pq-families/" class="badge-link" target="_blank" rel="noopener noreferrer" aria-label="Open crypto-lab-pq-families">crypto-lab-pq-families</a>
    </p>
    <p class="scripture">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</p>
    <a href="https://github.com/systemslibrarian/crypto-lab-mceliece-gate" class="github-badge"
       target="_blank" rel="noopener noreferrer" aria-label="View source on GitHub">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
      systemslibrarian/crypto-lab-mceliece-gate
    </a>
  </footer>`;
}

/* ======================================================================
   Layout Assembly
   ====================================================================== */

function buildPage(code: ToyGoppaCode, sc: ScrambledGenerator): string {
  return `
  <div class="app-container">
    ${renderHeader()}
    ${renderChips()}
    ${renderWhyMatters()}
    <main id="main-content" tabindex="-1">
      ${renderPrimer()}
      ${renderPanel1(code, sc)}
      ${renderPanel2()}
      ${renderPanel3(code)}
      ${renderPanel4()}
      ${renderPanel5()}
    </main>
    ${renderCrossLinks()}
    ${renderFooter()}
  </div>`;
}

/* ======================================================================
   Interactivity
   ====================================================================== */

function q<T extends HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}

function show(id: string, html: string): void {
  const el = q<HTMLDivElement>(id);
  if (el) {
    el.innerHTML = html;
    el.classList.add("visible");
  }
}

function clearOut(id: string): void {
  const el = q<HTMLDivElement>(id);
  if (el) { el.innerHTML = ""; el.classList.remove("visible"); }
}

function setStatus(text: string): void {
  const s = q<HTMLDivElement>("aria-live-status");
  if (s) s.textContent = text;
}

function setError(text: string): void {
  const s = q<HTMLDivElement>("error-status");
  if (s) s.textContent = text;
}

async function initPanel2(params: McElieceParams): Promise<void> {
  setStatus("Generating mceliece348864 public key for the size visualization…");
  const keypair = await generateKeypair(params);
  const hex = toHex(keypair.publicKey.slice(0, 8192), true);
  const hexArea = q<HTMLTextAreaElement>("pk-hex");
  if (hexArea) hexArea.value = hex;
  setStatus(`Public key generated: ${params.publicKeyBytes.toLocaleString()} bytes.`);
}

/**
 * Wire the structured/mixed/scrambled toggle in Panel 1. Re-renders the
 * matrix grid and caption in place; the three views are the real G, S·G,
 * and G_pub = S·G·P from scrambleGenerator().
 */
function initScrambleView(code: ToyGoppaCode, sc: ScrambledGenerator): void {
  const bob = q<HTMLButtonElement>("scramble-bob");
  const mixed = q<HTMLButtonElement>("scramble-mixed");
  const atk = q<HTMLButtonElement>("scramble-atk");
  const figure = q<HTMLDivElement>("scramble-figure");
  const caption = q<HTMLParagraphElement>("scramble-caption");
  if (!bob || !mixed || !atk || !figure || !caption) return;

  const buttons = [bob, mixed, atk];
  const ones = (m: number[][]): number =>
    m.reduce((a, r) => a + r.reduce((x, b) => x + b, 0), 0);

  const views = {
    bob: {
      btn: bob,
      matrix: code.generator,
      label: `Structured generator G, ${code.k} by ${code.n}`,
      caption: `<strong>Structured G (${code.k}×${code.n}).</strong> Note the tidy identity block on the left — the systematic structure Bob's trapdoor relies on. Total set bits: ${ones(code.generator)}.`
    },
    mixed: {
      btn: mixed,
      matrix: sc.mixed,
      label: `Row-mixed matrix S times G, ${code.k} by ${code.n}`,
      caption: `<strong>S · G (rows mixed).</strong> Multiplying by the invertible S adds rows together, so the clean identity block is already gone — but the columns have not moved yet. Set bits: ${ones(sc.mixed)}.`
    },
    atk: {
      btn: atk,
      matrix: sc.gPub,
      label: `Scrambled public generator G_pub, ${code.k} by ${code.n}`,
      caption: `<strong>Attacker sees G<sub>pub</sub> = S · G · P.</strong> The permutation P has now shuffled the columns too. No identity block, no visible Goppa structure — just a random-looking code. This is the public key. Set bits: ${ones(sc.gPub)}.`
    }
  } as const;

  const select = (key: keyof typeof views): void => {
    const v = views[key];
    buttons.forEach((b) => {
      const active = b === v.btn;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-pressed", String(active));
    });
    figure.innerHTML = renderMatrixGrid(v.matrix, v.label);
    caption.innerHTML = v.caption;
    setStatus(v.label);
  };

  bob.addEventListener("click", () => select("bob"));
  mixed.addEventListener("click", () => select("mixed"));
  atk.addEventListener("click", () => select("atk"));
}

function initPanel3(code: ToyGoppaCode): void {
  const btnEncap = q<HTMLButtonElement>("btn-encap");
  const btnTamper = q<HTMLButtonElement>("btn-tamper");
  const btnDecap = q<HTMLButtonElement>("btn-decap");
  const btnAttack = q<HTMLButtonElement>("btn-attack");
  const btnEncrypt = q<HTMLButtonElement>("btn-encrypt");
  const btnDecrypt = q<HTMLButtonElement>("btn-decrypt");
  if (!btnEncap || !btnTamper || !btnDecap || !btnAttack || !btnEncrypt || !btnDecrypt) return;

  let enc: ToyEncapsulation | null = null;
  let channel: number[] = []; // what Bob receives (possibly tampered)
  let tampered = false;
  let aesKey: CryptoKey | null = null;
  let encryptedData: { iv: Uint8Array; ciphertext: Uint8Array } | null = null;

  const resetDownstream = (): void => {
    btnDecap.disabled = false;
    btnAttack.disabled = true;
    btnEncrypt.disabled = true;
    btnDecrypt.disabled = true;
    aesKey = null;
    encryptedData = null;
    clearOut("out-decap");
    clearOut("out-attack");
    clearOut("out-aes");
  };

  const currentWeight = (): number =>
    enc ? channel.reduce((acc, bit, i) => acc + (bit !== enc!.codeword[i] ? 1 : 0), 0) : 0;

  /** Update just the live weight readout + over-radius warning, no re-render. */
  const refreshWeight = (): void => {
    const weight = currentWeight();
    const w = q<HTMLSpanElement>("ct-weight");
    if (w) w.textContent = String(weight);
    const warn = q<HTMLParagraphElement>("ct-warn");
    if (warn) warn.hidden = weight <= code.t;
  };

  const renderEncap = (): void => {
    if (!enc) return;
    show("out-encap", `
      <p><strong>Random message m (${code.k} bits):</strong></p>
      ${renderBitVector(enc.message)}
      <p><strong>Codeword m·G (${code.n} bits):</strong></p>
      ${renderBitVector(enc.codeword)}
      <p><strong>Error vector e:</strong> weight ${enc.errorPositions.length}, positions [${enc.errorPositions.join(", ")}]</p>
      <p><strong>Ciphertext C = m·G ⊕ e</strong> — tap any bit to add or remove an error:</p>
      ${renderEditableCiphertext(channel, enc.codeword)}
      <p class="panel-note">Current error weight: <strong id="ct-weight">${currentWeight()}</strong> / correction radius t = ${code.t}.</p>
      <p class="inline-warn" id="ct-warn" role="note"${currentWeight() <= code.t ? " hidden" : ""}>⚠ Error weight exceeds t = ${code.t}: Patterson decoding should now fail or produce the wrong secret.</p>
      <p><strong>Alice's shared secret K<sub>A</sub>:</strong> <span class="result-mono">${secretHex(enc.sharedSecret)}</span></p>
    `);
  };

  /** Toggle one ciphertext bit in place (preserves keyboard focus). */
  const toggleBit = (i: number, btn: HTMLButtonElement): void => {
    if (!enc) return;
    channel[i] ^= 1;
    const bit = channel[i];
    const isErr = bit !== enc.codeword[i];
    btn.textContent = String(bit);
    btn.classList.toggle("one", bit === 1);
    btn.classList.toggle("flipped", isErr);
    btn.setAttribute("aria-pressed", String(isErr));
    btn.setAttribute(
      "aria-label",
      `ciphertext bit ${i}, value ${bit}${isErr ? ", error — activate to clear" : " — activate to flip"}`
    );
    tampered = true;
    refreshWeight();
    resetDownstream();
    setStatus(`Bit ${i} toggled. Error weight is now ${currentWeight()}.`);
  };

  // Delegate clicks on the editable ciphertext bits.
  const outEncap = q<HTMLDivElement>("out-encap");
  outEncap?.addEventListener("click", (ev) => {
    const target = (ev.target as HTMLElement)?.closest<HTMLButtonElement>("button[data-bit]");
    if (target) toggleBit(Number(target.dataset.bit), target);
  });

  // Step 1: Encapsulate
  btnEncap.addEventListener("click", async () => {
    btnEncap.disabled = true;
    setError("");
    setStatus("Encapsulating…");
    try {
      enc = await encapsulate(code);
      channel = enc.ciphertext.slice();
      tampered = false;
      renderEncap();
      btnTamper.disabled = false;
      resetDownstream();
      setStatus(`Encapsulated. ${enc.errorPositions.length} errors injected. Proceed to decapsulation.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Encapsulation failed");
    } finally {
      btnEncap.disabled = false;
    }
  });

  // Step 1b: Tamper — add as many fresh errors as the current learner-edited
  // state needs to reach t + 1. A single flip is insufficient after the learner
  // has cleared one or more of the encapsulation errors.
  btnTamper.addEventListener("click", () => {
    if (!enc) return;
    setError("");
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    let pos = buf[0] % code.n;
    const isError = (i: number): boolean => channel[i] !== enc!.codeword[i];
    let needed = Math.max(0, code.t + 1 - currentWeight());
    let checked = 0;
    while (needed > 0 && checked < code.n) {
      if (!isError(pos)) {
        channel[pos] ^= 1;
        needed -= 1;
      }
      pos = (pos + 1) % code.n;
      checked += 1;
    }
    tampered = true;
    renderEncap();
    resetDownstream();
    const weight = currentWeight();
    setStatus(`Ciphertext tampered: error weight ${weight} exceeds the correction radius t = ${code.t}.`);
  });

  // Step 2: Decapsulate (Patterson)
  btnDecap.addEventListener("click", async () => {
    if (!enc) return;
    btnDecap.disabled = true;
    setError("");
    setStatus("Running Patterson decoding…");
    try {
      const { trace, sharedSecret } = await decapsulate(code, channel);
      const match = trace.success && toHex(sharedSecret) === toHex(enc.sharedSecret);
      const correctedSet = new Set<number>(trace.errorPositions);
      // `trace.success` is the code's OWN check that the corrected vector has a
      // zero syndrome, i.e. that it landed on a codeword. Over a complete census
      // of all 65,536 received vectors it is false for all 30,464 vectors more
      // than t away from a codeword — exactly the state the "Exceed correction
      // radius" button exists to create. Those three labels below used to be
      // printed unconditionally, so in every one of those states the page called
      // a non-codeword a "Corrected codeword", called bits that were never sent a
      // "Recovered message", and called σ's roots "located error positions".
      const decoded = trace.success;
      const weight = currentWeight();
      show("out-decap", `
        <p class="pchain-intro">Patterson turns the errors into the <em>roots of a polynomial</em>. Each step below moves closer to a polynomial whose roots are the error positions — ${decoded ? "which is exactly what happened here" : "which only works while the error weight stays within t; here it did not"} — open “why this step” to see what each transform buys you.</p>
        ${renderPattersonStep(
          "Syndrome S(z) = Σ 1/(z−α<sub>i</sub>):",
          polyStr(trace.syndrome),
          "the error's parity signature",
          "S(z) is the syndrome expressed as a polynomial: it depends only on <em>where</em> the errors are, not on the message. It is the fingerprint the parity check leaves — everything that follows is extracting the error positions back out of this one polynomial."
        )}
        ${trace.T ? renderPattersonStep(
          "T(z) = S(z)<sup>−1</sup> mod g:",
          polyStr(trace.T),
          "invert so errors become roots",
          "Inverting the syndrome modulo the Goppa polynomial g(z) flips the problem inside-out: the error positions, which were poles of S, become things we can solve for as roots. This is the move that makes the trapdoor work — it needs g(z), which only the key holder has."
        ) : ""}
        ${trace.R ? renderPattersonStep(
          "R(z) = √(T+z) mod g:",
          polyStr(trace.R),
          "factor the locator into a solvable size",
          "Taking the square root of T(z)+z (a real operation in a characteristic-2 field) sets up a split via the extended Euclidean algorithm into two smaller polynomials α and β. Splitting keeps their degrees within the correction radius t, so the locator we build next is guaranteed solvable when there are ≤ t errors."
        ) : ""}
        ${renderPattersonStep(
          "Error locator σ(z) = α² + z·β²:",
          polyStr(trace.sigma),
          "the polynomial whose roots ARE the error positions",
          decoded
            ? "This is the payoff. σ(z) is assembled from the split so that σ(α<sub>i</sub>) = 0 exactly at the support elements α<sub>i</sub> where an error occurred. Evaluate it across the support set (table below) and every zero points at a flipped bit — errors located, no searching required."
            : "That correspondence — σ(α<sub>i</sub>) = 0 exactly where an error occurred — holds only when the error weight is at most t. Past that radius the split still produces a σ(z), and it still has roots, but they are not the error positions: the corrected vector below has a non-zero syndrome, which is the code detecting that this σ is meaningless."
        )}
        <p><strong>${decoded ? "Located error positions (roots of σ)" : "Roots of σ — no valid error pattern to locate"}:</strong> [${trace.errorPositions.join(", ")}]</p>
        ${trace.errorPositions.length ? renderSigmaTable(code, trace.sigma, decoded) : ""}
        ${decoded
          ? `<p><strong>Corrected codeword:</strong></p>
        ${renderBitVector(trace.corrected, correctedSet)}
        <p><strong>Recovered message:</strong></p>
        ${renderBitVector(trace.message)}
        <p><strong>Bob's shared secret K<sub>B</sub>:</strong> <span class="result-mono">${secretHex(sharedSecret)}</span></p>`
          : `<p class="inline-warn" id="decode-failed-note" role="note">⚠ Patterson did <strong>not</strong> decode: the vector below still has a non-zero syndrome, so it is not a codeword. With error weight ${weight} against a correction radius of t = ${code.t} there is no weight-≤${code.t} pattern consistent with the syndrome, and σ(z)'s roots point at positions that were never flipped.</p>
        <p><strong>Vector after subtracting σ's roots — <em>not</em> a codeword:</strong></p>
        ${renderBitVector(trace.corrected, correctedSet)}
        <p><strong>Bits read from the information columns — <em>not</em> the message Alice sent:</strong></p>
        ${renderBitVector(trace.message)}
        <p><strong>Secret Bob would derive from those bits:</strong> <span class="result-mono">${secretHex(sharedSecret)}</span></p>`}
        <p><strong>Result:</strong> <span class="match-badge ${match ? "success" : "fail"}">${
          match
            ? "✓ K_A == K_B"
            : decoded
              ? "✗ Decoded to a different codeword — secrets differ"
              : `✗ Beyond the correction radius — error weight ${weight} > t = ${code.t}`
        }<span class="sr-only"> — shared secrets ${match ? "match" : "do not match"}</span></span></p>
      `);
      btnAttack.disabled = false;
      if (match) {
        aesKey = await deriveAesKey(sharedSecret);
        btnEncrypt.disabled = false;
        setStatus("Decapsulation succeeded. Shared secrets match.");
      } else {
        btnEncrypt.disabled = true;
        setStatus(
          decoded
            ? `Patterson decoded, but to a different codeword — the shared secrets differ (error weight ${weight}).`
            : `Patterson did not decode: error weight ${weight} exceeds the correction radius t = ${code.t}.`
        );
      }
    } catch (err) {
      // Defensive only. This branch used to claim "Undecodable — more than t
      // errors", but a complete census of all 2^n = 65,536 received vectors found
      // pattersonDecode() throwing 0 times: g(z) is irreducible, so every non-zero
      // syndrome is invertible mod g and the split always terminates. The
      // over-radius case does NOT arrive here — it returns normally with
      // trace.success === false and is handled above. So this must not name a
      // cause it cannot know.
      const reason = err instanceof Error ? err.message : String(err);
      show("out-decap", `
        <p><strong>Result:</strong> <span class="match-badge fail">✗ Decapsulation raised an error</span></p>
        <p>The decoder threw rather than returning a result: <code>${esc(reason)}</code>. This is not the over-radius lesson — that path returns a failed decode, not an exception.</p>
      `);
      btnAttack.disabled = false;
      btnEncrypt.disabled = true;
      setStatus("Decapsulation raised an error.");
    } finally {
      btnDecap.disabled = false;
    }
  });

  // Step 3: Attacker brute force
  btnAttack.addEventListener("click", () => {
    if (!enc) return;
    setError("");
    setStatus("Running brute-force syndrome decoding…");
    const result = bruteForceSyndromeDecode(code, channel);
    const toySpace = syndromeSearchSpace(code.n, code.t);
    const realN = 3488;
    const realT = 64;
    const realSpace = syndromeSearchSpace(realN, realT);
    const realExp = Math.round(Math.log2(realSpace));
    show("out-attack", `
      ${result
        ? `<p><strong>Brute force found:</strong> positions [${result.errorPositions.join(", ")}] after trying <strong>${result.searchSpace.toLocaleString()}</strong> patterns.</p>`
        : `<p><strong>Brute force found no weight-≤${code.t} solution</strong> (consistent with a tampered, undecodable ciphertext).</p>`}
      <p>Toy search space (weight ≤ ${code.t}, n=${code.n}): <strong>${toySpace.toLocaleString()}</strong> patterns — trivial.</p>
      <p>Real mceliece348864 (weight ≤ ${realT}, n=${realN}): <strong>≈ 2<sup>${realExp}</sup></strong> patterns to enumerate. The trapdoor turns this into a handful of field operations.</p>
      <p class="panel-note"><strong>That 2<sup>${realExp}</sup> is the size of the haystack, not the cost of the attack.</strong> Nobody enumerates patterns one at a time: the best known attack is information-set decoding, which the Classic McEliece submission estimates at roughly 2<sup>143</sup> operations for this parameter set (NIST Level 1, the AES-128 tier). Parameters are chosen from the ISD figure, not from the search-space count — the two differ by hundreds of bits, and quoting the larger one as the security level would overstate it enormously.</p>
      <div class="callout"><strong>That gap is the cryptosystem.</strong> Bob's (L, g) makes decoding polynomial; the attacker faces exponential syndrome decoding.</div>
    `);
    setStatus("Attacker comparison complete.");
  });

  // Step 4a: Encrypt
  btnEncrypt.addEventListener("click", async () => {
    btnEncrypt.disabled = true;
    setError("");
    const msg = q<HTMLTextAreaElement>("aes-message")?.value ?? "";
    if (!msg) { setError("Enter a message to encrypt."); btnEncrypt.disabled = false; return; }
    if (!aesKey) { setError("No AES key derived — decapsulate successfully first."); btnEncrypt.disabled = false; return; }
    setStatus("Encrypting with AES-256-GCM…");
    try {
      encryptedData = await encryptMessage(aesKey, msg);
      show("out-aes", `
        <p><strong>AES-256-GCM IV:</strong> <span class="result-mono">${toHex(encryptedData.iv)}</span></p>
        <p><strong>Ciphertext:</strong> <span class="result-mono">${toHex(encryptedData.ciphertext.slice(0, 64))}${encryptedData.ciphertext.length > 64 ? "…" : ""}</span></p>
        <p><strong>Ciphertext length:</strong> ${encryptedData.ciphertext.length} bytes</p>
      `);
      btnDecrypt.disabled = false;
      setStatus("Encrypted. Click Decrypt to verify the round-trip.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Encryption failed");
    } finally {
      btnEncrypt.disabled = false;
    }
  });

  // Step 4b: Decrypt
  btnDecrypt.addEventListener("click", async () => {
    btnDecrypt.disabled = true;
    setError("");
    if (!aesKey || !encryptedData) { setError("Encrypt a message first."); btnDecrypt.disabled = false; return; }
    setStatus("Decrypting…");
    try {
      const plaintext = await decryptMessage(aesKey, encryptedData.iv, encryptedData.ciphertext);
      const outEl = q<HTMLDivElement>("out-aes");
      if (outEl) {
        const p = document.createElement("p");
        const strong = document.createElement("strong");
        strong.textContent = "Decrypted: ";
        const span = document.createElement("span");
        span.textContent = plaintext; // user-originated text — set safely
        p.appendChild(strong);
        p.appendChild(span);
        outEl.appendChild(p);
      }
      setStatus("Decryption successful. Full KEM + DEM round-trip complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decryption failed");
    } finally {
      btnDecrypt.disabled = false;
    }
  });
}

/* ======================================================================
   Entry Point
   ====================================================================== */

export async function initUi(root: HTMLElement): Promise<void> {
  const code = buildToyGoppaCode();
  const scrambled = scrambleGenerator(code);
  root.innerHTML = buildPage(code, scrambled);

  initScrambleView(code, scrambled);
  initPanel3(code);
  await initPanel2(CLASSIC_MCELIECE_PARAMS[0]); // mceliece348864 hex dump
}
