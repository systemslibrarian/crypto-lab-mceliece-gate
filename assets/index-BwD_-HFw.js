(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const s of document.querySelectorAll('link[rel="modulepreload"]'))a(s);new MutationObserver(s=>{for(const i of s)if(i.type==="childList")for(const o of i.addedNodes)o.tagName==="LINK"&&o.rel==="modulepreload"&&a(o)}).observe(document,{childList:!0,subtree:!0});function r(s){const i={};return s.integrity&&(i.integrity=s.integrity),s.referrerPolicy&&(i.referrerPolicy=s.referrerPolicy),s.crossOrigin==="use-credentials"?i.credentials="include":s.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function a(s){if(s.ep)return;s.ep=!0;const i=r(s);fetch(s.href,i)}})();const E={m:4,primitivePolynomial:19};function T(e,t){return e^t}function K(e,t,r){let a=0,s=e,i=t;for(;i>0;)i&1&&(a^=s),i>>=1,s<<=1,s&1<<r.m&&(s^=r.primitivePolynomial);return a&(1<<r.m)-1}function I(e,t,r){let a=1;for(let s=0;s<t;s+=1)a=K(a,e,r);return a}function G(e,t){if(e===0)throw new Error("No inverse for zero in GF(2^m)");return I(e,(1<<t.m)-2,t)}function z(e,t,r){return e.reduce((a,s)=>T(K(a,t,r),s),0)}function O(){const e=[1,2,4,8,3,6,12,11],t=[1,0,1,1],r=[1,4,6],a=e.map((s,i)=>{if(!r.includes(i))return 0;const o=z(t,s,E);return G(o===0?1:o,E)});return{supportSet:e,goppaPolynomial:t,syndromeVector:a,generatorMatrix:["1 0 0 1 1 0 1 0","0 1 0 1 0 1 0 1","0 0 1 0 1 1 1 0"],scrambleMatrix:["1 1 0","0 1 1","1 0 1"],permutationMatrix:["0 0 1 0 0 0 0 0","1 0 0 0 0 0 0 0","0 0 0 1 0 0 0 0","0 1 0 0 0 0 0 0","0 0 0 0 0 1 0 0","0 0 0 0 1 0 0 0","0 0 0 0 0 0 0 1","0 0 0 0 0 0 1 0"]}}const H=[{name:"mceliece348864",level:"Level 1",n:3488,k:2720,t:64,publicKeyBytes:261120,ciphertextBytes:128},{name:"mceliece460896",level:"Level 3",n:4608,k:3360,t:96,publicKeyBytes:524160,ciphertextBytes:188},{name:"mceliece6688128",level:"Level 5",n:6688,k:5024,t:128,publicKeyBytes:1044992,ciphertextBytes:240},{name:"mceliece8192128",level:"Level 5 alt",n:8192,k:6528,t:128,publicKeyBytes:1357824,ciphertextBytes:240}],p=new TextEncoder;function M(e){const t=new Uint8Array(e);return crypto.getRandomValues(t),t}function $(e,t){const r=new Uint8Array(e.length);for(let a=0;a<e.length;a+=1)r[a]=e[a]^t[a];return r}function l(...e){const t=e.reduce((s,i)=>s+i.length,0),r=new Uint8Array(t);let a=0;for(const s of e)r.set(s,a),a+=s.length;return r}function y(e){return e.buffer.slice(e.byteOffset,e.byteOffset+e.byteLength)}async function d(e){const t=await crypto.subtle.digest("SHA-256",y(e));return new Uint8Array(t)}async function k(e,t){const r=[];let a=0,s=0;for(;s<t;){const i=new Uint8Array(4);new DataView(i.buffer).setUint32(0,a,!1);const o=await d(l(e,i));r.push(o),s+=o.length,a+=1}return l(...r).slice(0,t)}function b(e,t=!1){const r=Array.from(e,a=>a.toString(16).padStart(2,"0"));return t?r.join(" "):r.join("")}function N(e,t){const r=new Set;for(;r.size<e;)r.add(Math.floor(Math.random()*t));return[...r].sort((a,s)=>a-s)}async function _(e){const t=M(32),r=await d(l(p.encode("classic-mceliece-public"),t)),a=await k(r,e.publicKeyBytes),s=await d(a);return{params:e,publicKey:a,privateKey:{trapdoorSeed:t,publicKeyDigest:s,disclosedSimulation:!0}}}async function q(e,t){const r=await d(t),a=M(32),s=N(e.t,e.n),i=await d(p.encode(s.join(","))),o=l(a,i),h=await k(l(p.encode("enc-mask"),r),o.length),c=$(o,h),u=(await d(l(p.encode("tag"),o,r))).slice(0,16),n=new Uint8Array(e.ciphertextBytes);n.set(c.slice(0,Math.min(c.length,n.length)),0),n.length>c.length&&n.set(u.slice(0,Math.min(u.length,n.length-c.length)),c.length);const m=await d(l(p.encode("ss"),o,n));return{ciphertext:n,sharedSecret:m,messageMask:a,errorVectorPositions:s}}async function j(e,t){const a=await k(l(p.encode("enc-mask"),e.privateKey.publicKeyDigest),64),s=t.slice(0,64),i=$(s,a);return d(l(p.encode("ss"),i,t))}async function D(e){const t=await d(l(p.encode("aes-256-gcm"),e));return crypto.subtle.importKey("raw",y(t),{name:"AES-GCM"},!1,["encrypt","decrypt"])}async function R(e,t){const r=M(12),a=p.encode(t),s=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:y(r)},e,y(a)));return{iv:r,ciphertext:s}}async function U(e,t,r){const a=await crypto.subtle.decrypt({name:"AES-GCM",iv:y(t)},e,y(r));return new TextDecoder().decode(a)}const F=[{scheme:"Classic McEliece 348864",publicKeyBytes:261120,ciphertextBytes:128,keygenCycles:635e4,encapCycles:76e3,decapCycles:148e3,securityAssumption:"Syndrome decoding on random linear codes",yearsOfCryptanalysis:"46",source:"Classic McEliece submission benchmark package (Haswell ref cycles)"},{scheme:"ML-KEM-512",publicKeyBytes:800,ciphertextBytes:768,keygenCycles:123e3,encapCycles:165e3,decapCycles:191e3,securityAssumption:"Module-LWE",yearsOfCryptanalysis:"~8",source:"CRYSTALS-Kyber / ML-KEM submission benchmarks (Haswell ref cycles)"},{scheme:"BIKE-1",publicKeyBytes:1541,ciphertextBytes:1573,keygenCycles:488e4,encapCycles:633e4,decapCycles:781e4,securityAssumption:"QC-MDPC decoding",yearsOfCryptanalysis:"~10",source:"BIKE submission benchmark tables (Haswell ref cycles)"},{scheme:"HQC-128",publicKeyBytes:2249,ciphertextBytes:4433,keygenCycles:187e4,encapCycles:301e4,decapCycles:379e4,securityAssumption:"Code-based decoding in rank and Hamming metrics",yearsOfCryptanalysis:"~8",source:"HQC submission benchmark tables (Haswell ref cycles)"}];function f(e){return e>=1e6?`${(e/1e6).toFixed(2)} M cycles`:e>=1e3?`${(e/1e3).toFixed(0)} K cycles`:`${e} cycles`}const V=261120,C=[{name:"Classic McEliece mceliece348864 public key",bytes:261120,note:"NIST standardized parameter set"},{name:"ML-KEM-768 public key",bytes:1184,note:"NIST FIPS 203"},{name:"RSA-2048 public key",bytes:294,note:"DER SubjectPublicKeyInfo typical"},{name:"Average webpage payload",bytes:5e4,note:"Illustrative modern web median"},{name:"Typical profile photo",bytes:1e5,note:"Compressed JPEG example"}],S=[{name:"Classic McEliece 348864",bytes:261120},{name:"ML-KEM-512",bytes:800},{name:"ML-KEM-768",bytes:1184},{name:"ML-KEM-1024",bytes:1568},{name:"BIKE-1",bytes:1541},{name:"HQC-128",bytes:2249}];function g(e){return e>=1024*1024?`${(e/(1024*1024)).toFixed(2)} MB`:e>=1024?`${Math.round(e/1024)} KB`:`${e} B`}function P(e,t){return Math.max(2,Math.round(e/t*100))}function Q(e){return e.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}function Y(){const e=Math.max(...S.map(t=>t.bytes));return S.map(t=>{const r=P(t.bytes,e);return`
      <li class="bar-item">
        <div class="bar-row">
          <span>${t.name}</span>
          <span>${g(t.bytes)}</span>
        </div>
        <div class="bar-wrap" aria-hidden="true">
          <div class="bar-fill" style="width:${r}%"></div>
        </div>
      </li>`}).join("")}function W(){return F.map(e=>`
      <tr>
        <th scope="row">${e.scheme}</th>
        <td>${g(e.publicKeyBytes)}</td>
        <td>${g(e.ciphertextBytes)}</td>
        <td>${f(e.keygenCycles)}</td>
        <td>${f(e.encapCycles)}</td>
        <td>${f(e.decapCycles)}</td>
        <td>${e.securityAssumption}</td>
        <td>${e.yearsOfCryptanalysis}</td>
      </tr>`).join("")}function J(){const e=O(),t=Math.max(...C.map(a=>a.bytes)),r=C.map(a=>{const s=P(a.bytes,t);return`
      <article class="size-card" aria-label="${a.name} comparison card">
        <h4>${a.name}</h4>
        <p class="size-card-value">${a.bytes.toLocaleString()} bytes (${g(a.bytes)})</p>
        <div class="meter" role="img" aria-label="Relative size bar for ${a.name}">
          <span class="meter-fill" style="width:${s}%"></span>
        </div>
        <p>${a.note}</p>
      </article>`}).join("");return`
    <div class="page-shell" data-theme="dark">
      <header class="hero" aria-label="Demo header">
        <div class="hero-top">
          <span class="chip category-chip">Post-Quantum KEM</span>
          <button id="theme-toggle" class="theme-btn" aria-label="Toggle dark and light mode" aria-pressed="false" type="button">Toggle theme</button>
        </div>
        <h1>McEliece Gate</h1>
        <p class="subtitle">Classic McEliece in the browser: binary Goppa structure, massive keys, and conservative post-quantum assurance.</p>
        <div class="chip-row" aria-label="Primitive chips">
          <span class="chip">Classic McEliece</span>
          <span class="chip">Binary Goppa</span>
          <span class="chip">AES-256-GCM</span>
          <span class="chip">Code-Based</span>
        </div>
      </header>

      <main id="main-content" tabindex="-1">
        <section class="why-matters" aria-label="Why this matters">
          <h2>Why this matters</h2>
          <p>46 years of unbroken cryptanalysis make Classic McEliece the most conservative post-quantum choice available. The key size is the price of that confidence.</p>
          <p class="disclosure" role="note">Implementation disclosure: Illustrative - not production Classic McEliece. This demo accurately presents parameter sets and tradeoffs while using pedagogical simulation for browser interactivity.</p>
        </section>

        <section class="panel" aria-labelledby="panel1-title">
          <h2 id="panel1-title">Panel 1 - Binary Goppa Codes and the McEliece Construction</h2>
          <p>Error-correcting codes encode data, tolerate noise, and decode back to the original message. Classic McEliece uses binary Goppa codes defined over GF(2^m) with an irreducible support construction and Goppa polynomial g(z).</p>
          <p>Public key construction: Gpub = S * Ggoppa * P. The scramble matrix S and permutation matrix P hide the structured Goppa generator matrix so the public code appears random.</p>
          <p>Security assumption: hardness of syndrome decoding for random linear codes (McEliece 1978; Niederreiter 1986). Decoding random linear codes is NP-hard.</p>
          <p class="callout">Bridge: 46 years without a practical break - the most battle-tested PQ proposal in existence.</p>
          <div class="matrix-grid" aria-label="Toy matrix and syndrome visualization">
            <article aria-label="Toy generator matrix">
              <h3>Generator Matrix G</h3>
              <pre>${e.generatorMatrix.join(`
`)}</pre>
            </article>
            <article aria-label="Toy scramble matrix">
              <h3>Scramble Matrix S</h3>
              <pre>${e.scrambleMatrix.join(`
`)}</pre>
            </article>
            <article aria-label="Toy permutation matrix">
              <h3>Permutation Matrix P</h3>
              <pre>${e.permutationMatrix.join(`
`)}</pre>
            </article>
          </div>
          <p><strong>Binary Goppa toy values:</strong> support set L = [${e.supportSet.join(", ")}], g(z) coefficients = [${e.goppaPolynomial.join(", ")}], syndrome sample = [${e.syndromeVector.join(", ")}]</p>
        </section>

        <section class="panel" aria-labelledby="panel2-title">
          <h2 id="panel2-title">Panel 2 - The Key Size Problem (Make It Visceral)</h2>
          <p><strong>mceliece348864 public key size:</strong> 261,120 bytes = 255 KB.</p>
          <div class="size-grid" aria-label="Public key size comparisons">
            ${r}
          </div>
          <h3>All KEMs by public key size</h3>
          <ul class="bar-chart" aria-label="Public key size bar chart">${Y()}</ul>
          <label for="public-key-hex">Scrollable public key hex dump (first 8 KB rendered)</label>
          <textarea id="public-key-hex" class="hex-dump" readonly aria-label="Public key hex dump"></textarea>
          <p class="callout">This is the price of 46 years of cryptanalysis confidence.</p>
        </section>

        <section class="panel" aria-labelledby="panel3-title">
          <h2 id="panel3-title">Panel 3 - Encapsulation and Decapsulation</h2>
          <p>Alice encapsulates by sampling an error vector e with weight t and forming ciphertext data. In production Classic McEliece this is tied to Goppa decoding; this demo keeps parameters exact while emulating the trapdoor flow for clarity.</p>
          <div class="actions">
            <button id="run-kem" type="button" aria-label="Run key generation, encapsulation, and decapsulation demo">Run KEM + DEM Flow</button>
          </div>
          <div id="aria-status" class="sr-only" role="status" aria-live="polite"></div>
          <div id="error-status" class="error" role="alert" aria-live="assertive"></div>
          <div id="kem-output" class="output" aria-label="Encapsulation and decapsulation output"></div>
        </section>

        <section class="panel" aria-labelledby="panel4-title">
          <h2 id="panel4-title">Panel 4 - The Tradeoff Visualization</h2>
          <p>Classic McEliece offers tiny ciphertexts with enormous public keys. The table below uses published benchmark sources from NIST submission packages.</p>
          <div class="table-wrap" aria-label="KEM tradeoff comparison table">
            <table>
              <caption>mceliece348864 vs ML-KEM-512 vs BIKE-1 vs HQC-128</caption>
              <thead>
                <tr>
                  <th scope="col">Scheme</th>
                  <th scope="col">Public key</th>
                  <th scope="col">Ciphertext</th>
                  <th scope="col">Keygen</th>
                  <th scope="col">Encap</th>
                  <th scope="col">Decap</th>
                  <th scope="col">Security assumption</th>
                  <th scope="col">Years of cryptanalysis</th>
                </tr>
              </thead>
              <tbody>
                ${W()}
              </tbody>
            </table>
          </div>
          <p class="callout">Key insight: McEliece has the smallest ciphertext among major code-based contenders here, but by far the largest public key.</p>
          <h3>Use-case matrix</h3>
          <ul>
            <li>Long-term archival encryption</li>
            <li>Government and military high-assurance systems</li>
            <li>Hybrid PQ deployment where key size is not the bottleneck</li>
            <li>Store-now decrypt-later threat model</li>
          </ul>
        </section>

        <section class="panel" aria-labelledby="panel5-title">
          <h2 id="panel5-title">Panel 5 - Why 46 Years Matters</h2>
          <ol class="timeline" aria-label="Classic McEliece timeline">
            <li><strong>1978:</strong> McEliece proposes code-based public-key encryption.</li>
            <li><strong>1986:</strong> Niederreiter reformulates the code-based trapdoor via syndrome decoding.</li>
            <li><strong>1978-2024:</strong> Information-set decoding improves, but best attacks remain exponential.</li>
            <li><strong>2024:</strong> NIST standardizes Classic McEliece for PQ KEM use in high assurance contexts.</li>
          </ol>
          <p>No known quantum speedup is better than square-root style search acceleration (Grover-like), which does not collapse McEliece security.</p>
          <p>Lattice systems have moved faster in deployment and cryptanalysis iteration; McEliece is the conservative choice when 50-year secrecy dominates bandwidth concerns.</p>
          <div class="link-row" aria-label="Related demo links">
            <a href="https://github.com/systemslibrarian/crypto-lab-bike-vault" target="_blank" rel="noopener noreferrer" class="badge" aria-label="Open crypto-lab-bike-vault repository">crypto-lab-bike-vault</a>
            <a href="https://github.com/systemslibrarian/crypto-lab-hqc-vault" target="_blank" rel="noopener noreferrer" class="badge" aria-label="Open crypto-lab-hqc-vault repository">crypto-lab-hqc-vault</a>
            <a href="https://github.com/systemslibrarian/crypto-lab-kyber-vault" target="_blank" rel="noopener noreferrer" class="badge" aria-label="Open crypto-lab-kyber-vault repository">crypto-lab-kyber-vault</a>
            <a href="https://github.com/systemslibrarian/crypto-compare" target="_blank" rel="noopener noreferrer" class="badge" aria-label="Open crypto-compare repository">crypto-compare KEM category</a>
          </div>
          <p class="citation">References: McEliece (1978), Niederreiter (1986), NIST FIPS 203 and NIST Classic McEliece standardization documentation.</p>
        </section>
      </main>

      <footer class="footer" aria-label="Footer">
        <a href="https://github.com/systemslibrarian/crypto-lab-mceliece-gate" target="_blank" rel="noopener noreferrer" class="badge" aria-label="Open GitHub repository for this demo">GitHub: systemslibrarian/crypto-lab-mceliece-gate</a>
        <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
      </footer>
    </div>
  `}function Z(e,t=8192){return b(e.slice(0,t),!0)}async function X(e){e.innerHTML=J();const t=e.querySelector(".page-shell"),r=e.querySelector("#theme-toggle"),a=e.querySelector("#run-kem"),s=e.querySelector("#aria-status"),i=e.querySelector("#error-status"),o=e.querySelector("#kem-output"),h=e.querySelector("#public-key-hex");if(!t||!r||!a||!s||!i||!o||!h)throw new Error("UI elements missing");const c=H[0],u=await _(c);h.value=Z(u.publicKey),r.addEventListener("click",()=>{const n=t.dataset.theme==="dark"?"light":"dark";t.dataset.theme=n,r.setAttribute("aria-pressed",String(n==="light")),s.textContent=`Theme switched to ${n} mode.`}),a.addEventListener("click",async()=>{i.textContent="",o.innerHTML="",s.textContent="Running key encapsulation demo.",a.disabled=!0;try{const n=await q(c,u.publicKey),m=await j(u,n.ciphertext),B=b(n.sharedSecret)===b(m),w=await D(n.sharedSecret),x=await R(w,"Long-horizon confidential message."),A=await U(w,x.iv,x.ciphertext),L=[`<p><strong>Parameter set:</strong> ${c.name} (${c.level}) with n=${c.n}, k=${c.k}, t=${c.t}</p>`,`<p><strong>Public key size:</strong> ${c.publicKeyBytes.toLocaleString()} bytes</p>`,`<p><strong>Ciphertext size:</strong> ${c.ciphertextBytes} bytes (tiny compared with public key)</p>`,`<p><strong>Alice error vector weight:</strong> ${n.errorVectorPositions.length} non-zero positions</p>`,`<p><strong>Sample positions:</strong> ${n.errorVectorPositions.slice(0,16).join(", ")}${n.errorVectorPositions.length>16?" ...":""}</p>`,`<p><strong>Shared secrets match:</strong> ${B?"Yes (K_Alice == K_Bob)":"No"}</p>`,`<p><strong>AES-256-GCM decrypted message:</strong> ${Q(A)}</p>`,`<p><strong>Ciphertext hex preview:</strong> ${b(n.ciphertext.slice(0,48),!0)} ...</p>`,`<p><strong>Shared secret preview:</strong> ${b(n.sharedSecret.slice(0,16),!0)} ...</p>`];o.innerHTML=L.join(`
`),s.textContent="KEM and AES flow completed successfully."}catch(n){const m=n instanceof Error?n.message:"Unknown KEM demo error";i.textContent=`Error: ${m}`,s.textContent="KEM flow failed."}finally{a.disabled=!1}}),s.textContent=`Loaded ${c.name} with exact NIST parameters and ${V.toLocaleString()} byte public key.`}const v=document.querySelector("#app");if(!v)throw new Error("App root not found");X(v).catch(e=>{const t=e instanceof Error?e.message:"Unknown startup error";v.innerHTML=`<p role="alert">Failed to initialize demo: ${t}</p>`});
