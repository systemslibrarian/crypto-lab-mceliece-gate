import { buildToyGoppaVisual } from "./goppa";
import {
  CLASSIC_MCELIECE_PARAMS,
  decapsulate,
  decryptMessage,
  deriveAesKey,
  encapsulate,
  encryptMessage,
  generateKeypair,
  toHex,
  type SimulatedKeypair,
  type McElieceParams
} from "./mceliece";
import { COMPARISON_ROWS, formatCycles } from "./compare";
import {
  KEM_PUBLIC_KEY_BENCHMARKS,
  SIZE_COMPARISONS,
  formatBytes,
  proportion
} from "./keysize";

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

function getEffectiveTheme(): string {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit) return explicit;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
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

/* ======================================================================
   HTML builders — each returns an HTML string
   ====================================================================== */

function renderHeader(): string {
  const isDark = getEffectiveTheme() === "dark";
  const label = isDark ? "Switch to light mode" : "Switch to dark mode";
  const icon = isDark ? "\u2600\ufe0f" : "\u{1f319}";
  return `
  <header class="demo-header" aria-label="Demo header">
    <div class="header-top">
      <span class="category-chip">Post-Quantum KEM</span>
      <button id="theme-toggle" class="theme-toggle" type="button"
              aria-label="${label}"><span aria-hidden="true">${icon}</span> <span id="theme-label">${isDark ? "Light" : "Dark"}</span></button>
    </div>
    <h1>McEliece Gate</h1>
    <p class="subtitle">Classic McEliece in the browser — binary Goppa structure, massive keys, and conservative post-quantum assurance.</p>
  </header>`;
}

function renderChips(): string {
  return `
  <div class="primitive-chips" aria-label="Cryptographic primitives used">
    <span class="chip">Classic McEliece</span>
    <span class="chip">Binary Goppa</span>
    <span class="chip">AES-256-GCM</span>
    <span class="chip">Code-Based</span>
  </div>`;
}

function renderWhyMatters(): string {
  return `
  <section class="why-matters" aria-label="Why this matters">
    <h2>Why This Matters</h2>
    <p>46 years of unbroken cryptanalysis make Classic McEliece the most conservative post-quantum choice available. The key size is the price of that confidence.</p>
    <div class="disclosure" role="note">
      <strong>Illustrative — not production Classic McEliece.</strong> Parameter sets, key sizes, and security properties are exact per the NIST PQC standard. The cryptographic operations use pedagogical simulation for browser interactivity.
    </div>
  </section>`;
}

/* --- Panel 1: Binary Goppa Codes ------------------------------ */

function renderPanel1(): string {
  const g = buildToyGoppaVisual();
  return `
  <section class="panel" id="panel-1" aria-labelledby="p1-title">
    <h2 class="panel-title" id="p1-title">1. Binary Goppa Codes and the McEliece Construction</h2>

    <p><strong>Error-correcting codes</strong> encode data so that even if errors are introduced, the original message can be recovered. Binary Goppa codes are a family of algebraic codes defined over GF(2<sup>m</sup>) by an irreducible Goppa polynomial g(z).</p>

    <h3 class="panel-subtitle">The McEliece Construction</h3>
    <p>The public key is formed as: <code>G<sub>pub</sub> = S &middot; G<sub>goppa</sub> &middot; P</code></p>
    <p>The scramble matrix <strong>S</strong> and permutation matrix <strong>P</strong> disguise the structured Goppa generator matrix so the public code looks like a random linear code. An attacker who can only see G<sub>pub</sub> faces the problem of decoding a random linear code — known to be NP-hard.</p>

    <h3 class="panel-subtitle">Security Assumption</h3>
    <p>Hardness of <strong>syndrome decoding</strong> on random binary linear codes (McEliece 1978; Niederreiter 1986). The best known attacks — information-set decoding — remain exponential in complexity.</p>

    <div class="callout">46 years without a practical break — the most battle-tested post-quantum proposal in existence.</div>

    <h3 class="panel-subtitle">Toy Visualization (GF(2<sup>4</sup>))</h3>
    <p class="panel-note">Below is a pedagogical toy example over GF(16) illustrating the matrix structures. Real Classic McEliece uses GF(2<sup>12</sup>) or GF(2<sup>13</sup>) with thousands of columns.</p>

    <div class="matrix-grid" aria-label="Toy matrix visualization">
      <div class="matrix-card" aria-label="Generator matrix G">
        <h4>Generator G</h4>
        <pre>${g.generatorMatrix.join("\n")}</pre>
      </div>
      <div class="matrix-card" aria-label="Scramble matrix S">
        <h4>Scramble S</h4>
        <pre>${g.scrambleMatrix.join("\n")}</pre>
      </div>
      <div class="matrix-card" aria-label="Permutation matrix P">
        <h4>Permutation P</h4>
        <pre>${g.permutationMatrix.join("\n")}</pre>
      </div>
    </div>

    <p><strong>Support set L</strong> = [${g.supportSet.join(", ")}]<br>
    <strong>Goppa polynomial g(z)</strong> coefficients = [${g.goppaPolynomial.join(", ")}]<br>
    <strong>Syndrome sample</strong> = [${g.syndromeVector.join(", ")}]</p>
  </section>`;
}

/* --- Panel 2: Key Size Problem -------------------------------- */

function renderSizeCards(): string {
  const max = Math.max(...SIZE_COMPARISONS.map((e) => e.bytes));
  return SIZE_COMPARISONS.map((e) => {
    const pct = proportion(e.bytes, max);
    return `
    <div class="size-card" aria-label="${e.name}: ${e.bytes.toLocaleString()} bytes">
      <h4>${esc(e.name)}</h4>
      <span class="size-card-value">${e.bytes.toLocaleString()} bytes (${formatBytes(e.bytes)})</span>
      <div class="meter" role="img" aria-label="Relative size: ${pct}%">
        <span class="meter-fill" style="width:${pct}%"></span>
      </div>
      <span class="size-card-note">${esc(e.note)}</span>
    </div>`;
  }).join("");
}

function renderKemBars(): string {
  const max = Math.max(...KEM_PUBLIC_KEY_BENCHMARKS.map((k) => k.bytes));
  return KEM_PUBLIC_KEY_BENCHMARKS.map((k) => {
    const pct = proportion(k.bytes, max);
    const tag = schemeTag(k.name);
    return `
    <li class="bar-item" aria-label="${esc(k.name)}: ${formatBytes(k.bytes)}">
      <div class="bar-label">
        <span>${esc(k.name)}</span>
        <span class="bar-value">${formatBytes(k.bytes)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" data-scheme="${tag}" style="width:${pct}%" role="img" aria-label="${pct}% of maximum"></div>
      </div>
    </li>`;
  }).join("");
}

function renderPanel2(): string {
  return `
  <section class="panel" id="panel-2" aria-labelledby="p2-title">
    <h2 class="panel-title" id="p2-title">2. The Key Size Problem (Make It Visceral)</h2>

    <p>The smallest Classic McEliece parameter set — <strong>mceliece348864</strong> (NIST Level 1) — has a <strong>261,120-byte</strong> public key. That is 255 KB for one public key.</p>

    <h3 class="panel-subtitle">How Big Is 261 KB?</h3>
    <div class="size-grid" aria-label="Public key size comparisons">
      ${renderSizeCards()}
    </div>

    <p>One McEliece public key equals <strong>~220</strong> ML-KEM-768 keys or <strong>~888</strong> RSA-2048 keys. It is roughly five times the size of an average webpage.</p>

    <h3 class="panel-subtitle">All NIST PQ KEMs by Public Key Size</h3>
    <ul class="bar-chart" aria-label="Public key size comparison bar chart">
      ${renderKemBars()}
    </ul>

    <h3 class="panel-subtitle">Public Key Hex Dump</h3>
    <p>A live hex dump of the first 8 KB of a generated mceliece348864 public key. Scroll to feel the scale.</p>
    <label for="pk-hex" class="sr-only">Public key hex dump (first 8192 bytes)</label>
    <textarea id="pk-hex" class="hex-dump" readonly aria-label="Public key hex dump, first 8192 bytes">Generating…</textarea>

    <div class="callout">This is the price of 46 years of cryptanalysis confidence.</div>
  </section>`;
}

/* --- Panel 3: Encapsulation / Decapsulation ------------------- */

function renderPanel3(): string {
  return `
  <section class="panel" id="panel-3" aria-labelledby="p3-title">
    <h2 class="panel-title" id="p3-title">3. Encapsulation and Decapsulation</h2>

    <div id="aria-live-status" class="aria-status" role="status" aria-live="polite"></div>
    <div id="error-status" class="error-status" role="alert" aria-live="assertive"></div>

    <!-- Step 1: Keygen -->
    <div class="step" id="step-keygen">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">1</span>
        <span class="step-title">Key Generation</span>
      </div>
      <p>Generate a Classic McEliece keypair using the <strong>mceliece348864</strong> parameter set (n=3488, k=2720, t=64).</p>
      <div class="btn-row">
        <button id="btn-keygen" class="btn btn-primary" type="button" aria-label="Generate Classic McEliece keypair">Generate Keypair</button>
      </div>
      <div id="out-keygen" class="output-area" aria-label="Key generation output"></div>
    </div>

    <!-- Step 2: Encapsulation -->
    <div class="step" id="step-encap">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">2</span>
        <span class="step-title">Encapsulation (Alice)</span>
      </div>
      <p>Alice samples an error vector <strong>e</strong> of weight t=${CLASSIC_MCELIECE_PARAMS[0].t} and computes a ciphertext. The ciphertext is tiny: only <strong>${CLASSIC_MCELIECE_PARAMS[0].ciphertextBytes} bytes</strong> despite the enormous public key.</p>
      <div class="btn-row">
        <button id="btn-encap" class="btn btn-primary" type="button" disabled aria-label="Encapsulate shared secret">Encapsulate</button>
      </div>
      <div id="out-encap" class="output-area" aria-label="Encapsulation output"></div>
    </div>

    <!-- Step 3: Decapsulation -->
    <div class="step" id="step-decap">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">3</span>
        <span class="step-title">Decapsulation (Bob)</span>
      </div>
      <p>Bob uses the private key (Patterson algorithm in production) to decode the Goppa code, recover the error vector, and derive the same shared secret.</p>
      <div class="btn-row">
        <button id="btn-decap" class="btn btn-primary" type="button" disabled aria-label="Decapsulate shared secret">Decapsulate</button>
      </div>
      <div id="out-decap" class="output-area" aria-label="Decapsulation output"></div>
    </div>

    <!-- Step 4: AES-256-GCM -->
    <div class="step" id="step-aes">
      <div class="step-header">
        <span class="step-number" aria-hidden="true">4</span>
        <span class="step-title">AES-256-GCM Wrap (KEM + DEM)</span>
      </div>
      <p>The shared secret is fed into AES-256-GCM to encrypt and decrypt a message end-to-end.</p>
      <div class="input-group">
        <label for="aes-message">Message to encrypt</label>
        <textarea id="aes-message" rows="2">Classic McEliece: conservative post-quantum security since 1978.</textarea>
      </div>
      <div class="btn-row">
        <button id="btn-encrypt" class="btn btn-primary" type="button" disabled aria-label="Encrypt message with AES-256-GCM">Encrypt</button>
        <button id="btn-decrypt" class="btn btn-secondary" type="button" disabled aria-label="Decrypt ciphertext">Decrypt</button>
      </div>
      <div id="out-aes" class="output-area" aria-label="AES encryption and decryption output"></div>
    </div>

    <p><strong>Note:</strong> The ciphertext is tiny (${CLASSIC_MCELIECE_PARAMS[0].ciphertextBytes} bytes) despite the enormous public key (${formatBytes(CLASSIC_MCELIECE_PARAMS[0].publicKeyBytes)}) — an asymmetric tradeoff unique to Classic McEliece.</p>
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
      <td>${r.yearsOfCryptanalysis} years</td>
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
    <div class="use-case-card">
      <h4>${esc(c.title)}</h4>
      <p>${esc(c.desc)}</p>
      <span class="recommend-tag ${c.rec}" aria-label="${esc(c.recLabel)}">${esc(c.recLabel)}</span>
    </div>`).join("");
}

function renderPanel4(): string {
  return `
  <section class="panel" id="panel-4" aria-labelledby="p4-title">
    <h2 class="panel-title" id="p4-title">4. The Tradeoff Visualization</h2>

    <p>Classic McEliece has the <strong>smallest ciphertext</strong> of any code-based KEM but the <strong>largest public key</strong> by orders of magnitude. The table uses published NIST submission benchmarks (Haswell reference cycles).</p>

    <div class="table-wrap" role="region" aria-label="KEM comparison table" tabindex="0">
      <table class="comparison-table">
        <caption class="sr-only">mceliece348864 vs ML-KEM-512 vs BIKE-1 vs HQC-128</caption>
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

    <div class="callout"><strong>Key insight:</strong> McEliece has the smallest ciphertext among major code-based contenders but by far the largest public key. The "years of cryptanalysis" column tells the story — 46 years vs ~8 for lattice-based alternatives.</div>

    <h3 class="panel-subtitle">When Is McEliece Worth the Key Size?</h3>
    <div class="use-case-grid" aria-label="Use case matrix">
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
    { year: "2024", text: "NIST standardizes Classic McEliece. 46 years of cryptanalysis, zero practical breaks." }
  ];

  const timeline = events.map((e) => `
    <li class="timeline-item">
      <span class="timeline-year">${e.year}</span>
      <span class="timeline-text">${esc(e.text)}</span>
    </li>`).join("");

  return `
  <section class="panel" id="panel-5" aria-labelledby="p5-title">
    <h2 class="panel-title" id="p5-title">5. Why 46 Years Matters</h2>

    <ul class="timeline" aria-label="Classic McEliece cryptanalysis timeline">
      ${timeline}
    </ul>

    <h3 class="panel-subtitle">No Quantum Shortcut</h3>
    <p>No known quantum speedup is better than square-root search acceleration (Grover-like). Unlike lattice problems, where sub-exponential quantum attacks remain an active area of research, syndrome decoding on random linear codes has no known path to polynomial quantum speedup.</p>

    <h3 class="panel-subtitle">The Conservative Choice</h3>
    <p>Lattice-based algorithms (ML-KEM/Kyber) have seen significant cryptanalytic progress: NTRU subfield attacks, parameter adjustments, and ongoing structural exploration. Classic McEliece's security assumption has been studied since 1978 — if you need to encrypt something that must stay secret for 50 years, McEliece is the most defensible choice.</p>

    <p>Classic McEliece appears in government and defense research contexts where the cost of being wrong is catastrophic and key size is an acceptable tradeoff.</p>

    <div class="callout"><strong>References:</strong> McEliece (1978), Niederreiter (1986), Bernstein-Lange-Peters (2008), NIST FIPS for Classic McEliece standardization.</div>
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

function buildPage(): string {
  return `
  <div class="app-container">
    ${renderHeader()}
    ${renderChips()}
    ${renderWhyMatters()}
    <main id="main-content" tabindex="-1">
      ${renderPanel1()}
      ${renderPanel2()}
      ${renderPanel3()}
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

function initThemeToggle(): void {
  let saved: string | null = null;
  try { saved = localStorage.getItem("mceliece-gate-theme"); } catch { /* storage unavailable */ }
  if (saved === "dark" || saved === "light") {
    document.documentElement.setAttribute("data-theme", saved);
  }

  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  function updateLabel(): void {
    const current = getEffectiveTheme();
    const labelEl = document.getElementById("theme-label");
    const iconSpan = btn!.querySelector("span[aria-hidden]");
    if (labelEl) labelEl.textContent = current === "dark" ? "Light" : "Dark";
    if (iconSpan) iconSpan.textContent = current === "dark" ? "\u2600\ufe0f" : "\u{1f319}";
    btn!.setAttribute("aria-label", current === "dark" ? "Switch to light mode" : "Switch to dark mode");
  }

  updateLabel();

  btn.addEventListener("click", () => {
    const next = getEffectiveTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("mceliece-gate-theme", next); } catch { /* storage unavailable */ }
    updateLabel();
  });
}

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

function setStatus(text: string): void {
  const s = q<HTMLDivElement>("aria-live-status");
  if (s) s.textContent = text;
}

function setError(text: string): void {
  const s = q<HTMLDivElement>("error-status");
  if (s) s.textContent = text;
}

async function initPanel2(params: McElieceParams): Promise<SimulatedKeypair> {
  setStatus("Generating mceliece348864 keypair for key size visualization…");
  const keypair = await generateKeypair(params);
  const hex = toHex(keypair.publicKey.slice(0, 8192), true);
  const hexArea = q<HTMLTextAreaElement>("pk-hex");
  if (hexArea) hexArea.value = hex;
  setStatus(`Keypair generated. Public key: ${params.publicKeyBytes.toLocaleString()} bytes.`);
  return keypair;
}

function initPanel3(params: McElieceParams, initialKeypair: SimulatedKeypair): void {
  const btnKeygen = q<HTMLButtonElement>("btn-keygen");
  const btnEncap = q<HTMLButtonElement>("btn-encap");
  const btnDecap = q<HTMLButtonElement>("btn-decap");
  const btnEncrypt = q<HTMLButtonElement>("btn-encrypt");
  const btnDecrypt = q<HTMLButtonElement>("btn-decrypt");

  if (!btnKeygen || !btnEncap || !btnDecap || !btnEncrypt || !btnDecrypt) return;

  let keypair: SimulatedKeypair = initialKeypair;
  let aliceSecret: Uint8Array | null = null;
  let bobSecret: Uint8Array | null = null;
  let aesKey: CryptoKey | null = null;
  let encryptedData: { iv: Uint8Array; ciphertext: Uint8Array } | null = null;

  // Step 1: Keygen
  btnKeygen.addEventListener("click", async () => {
    btnKeygen.disabled = true;
    setError("");
    setStatus("Generating keypair…");
    try {
      keypair = await generateKeypair(params);
      show("out-keygen", `
        <p><strong>Parameter set:</strong> ${params.name} (${params.level})</p>
        <p><strong>n =</strong> ${params.n}, <strong>k =</strong> ${params.k}, <strong>t =</strong> ${params.t}</p>
        <p><strong>Public key:</strong> ${params.publicKeyBytes.toLocaleString()} bytes (${formatBytes(params.publicKeyBytes)})</p>
        <p><strong>Private key trapdoor seed:</strong> <span class="result-mono">${toHex(keypair.privateKey.trapdoorSeed.slice(0, 16))}…</span></p>
      `);
      btnEncap.disabled = false;
      btnDecap.disabled = true;
      btnEncrypt.disabled = true;
      btnDecrypt.disabled = true;
      aliceSecret = null;
      bobSecret = null;
      aesKey = null;
      encryptedData = null;
      // Clear stale output from previous runs
      for (const id of ["out-encap", "out-decap", "out-aes"]) {
        const el = q<HTMLDivElement>(id);
        if (el) { el.innerHTML = ""; el.classList.remove("visible"); }
      }
      setStatus("Keypair generated. Proceed to encapsulation.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Keygen failed");
    } finally {
      btnKeygen.disabled = false;
    }
  });

  // Step 2: Encapsulation
  btnEncap.addEventListener("click", async () => {
    btnEncap.disabled = true;
    setError("");
    setStatus("Encapsulating shared secret…");
    try {
      const result = await encapsulate(params, keypair.publicKey);
      aliceSecret = result.sharedSecret;
      const posPreview = result.errorVectorPositions.slice(0, 12).join(", ");
      const more = result.errorVectorPositions.length > 12 ? " …" : "";
      show("out-encap", `
        <p><strong>Ciphertext size:</strong> ${params.ciphertextBytes} bytes</p>
        <p><strong>Ciphertext:</strong> <span class="result-mono">${toHex(result.ciphertext.slice(0, 48))}…</span></p>
        <p><strong>Error vector weight:</strong> ${result.errorVectorPositions.length} positions</p>
        <p><strong>Sample positions:</strong> ${posPreview}${more}</p>
        <p><strong>Alice shared secret:</strong> <span class="result-mono">${toHex(result.sharedSecret.slice(0, 16))}…</span></p>
      `);
      // Store ciphertext for decap
      (keypair as SimulatedKeypair & { _ct?: Uint8Array })._ct = result.ciphertext;
      btnDecap.disabled = false;
      setStatus("Encapsulation complete. Proceed to decapsulation.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Encapsulation failed");
      btnEncap.disabled = false;
    }
  });

  // Step 3: Decapsulation
  btnDecap.addEventListener("click", async () => {
    btnDecap.disabled = true;
    setError("");
    setStatus("Decapsulating shared secret…");
    try {
      const ct = (keypair as SimulatedKeypair & { _ct?: Uint8Array })._ct;
      if (!ct) throw new Error("No ciphertext — run encapsulation first.");
      bobSecret = await decapsulate(keypair, ct);
      const match = aliceSecret !== null && toHex(aliceSecret) === toHex(bobSecret);
      show("out-decap", `
        <p><strong>Bob shared secret:</strong> <span class="result-mono">${toHex(bobSecret.slice(0, 16))}…</span></p>
        <p><strong>Secrets match:</strong> <span class="match-badge ${match ? "success" : "fail"}" aria-label="Shared secrets ${match ? "match" : "do not match"}">${match ? "✓ K_Alice == K_Bob" : "✗ Mismatch"}</span></p>
      `);
      if (match) {
        aesKey = await deriveAesKey(bobSecret);
        btnEncrypt.disabled = false;
      }
      setStatus(match ? "Shared secrets match. Proceed to AES-256-GCM." : "Shared secret mismatch.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decapsulation failed");
      btnDecap.disabled = false;
    }
  });

  // Step 4a: Encrypt
  btnEncrypt.addEventListener("click", async () => {
    btnEncrypt.disabled = true;
    setError("");
    const msg = q<HTMLTextAreaElement>("aes-message")?.value ?? "";
    if (!msg) { setError("Enter a message to encrypt."); btnEncrypt.disabled = false; return; }
    if (!aesKey) { setError("No AES key derived."); btnEncrypt.disabled = false; return; }
    setStatus("Encrypting with AES-256-GCM…");
    try {
      encryptedData = await encryptMessage(aesKey, msg);
      show("out-aes", `
        <p><strong>AES-256-GCM IV:</strong> <span class="result-mono">${toHex(encryptedData.iv)}</span></p>
        <p><strong>Ciphertext:</strong> <span class="result-mono">${toHex(encryptedData.ciphertext.slice(0, 64))}${encryptedData.ciphertext.length > 64 ? "…" : ""}</span></p>
        <p><strong>Ciphertext length:</strong> ${encryptedData.ciphertext.length} bytes</p>
      `);
      btnDecrypt.disabled = false;
      setStatus("Encrypted. Click Decrypt to verify round-trip.");
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
        // Append decrypted output safely using textContent for user-originated text
        const p = document.createElement("p");
        const strong = document.createElement("strong");
        strong.textContent = "Decrypted: ";
        const span = document.createElement("span");
        span.textContent = plaintext;
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
  root.innerHTML = buildPage();

  initThemeToggle();

  const params = CLASSIC_MCELIECE_PARAMS[0]; // mceliece348864
  const keypair = await initPanel2(params);
  initPanel3(params, keypair);
}
