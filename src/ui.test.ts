// @vitest-environment jsdom
import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { webcrypto } from "node:crypto";

beforeAll(() => {
  // Deterministically use Node's WebCrypto for SHA-256 / AES-GCM rather than
  // whatever the jsdom/Node combo exposes (which varies across CI runners).
  try {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  } catch {
    /* already non-configurable; the source passes ArrayBufferViews, which
       SubtleCrypto accepts cross-realm, so this is fine. */
  }
});

beforeEach(() => {
  // Each test mounts a fresh page so getElementById can't hit stale nodes.
  document.body.innerHTML = "";
});

async function waitFor(predicate: () => boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("UI integration (jsdom)", () => {
  it("mounts every panel and runs a full encapsulate → decapsulate round-trip", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);

    await initUi(root);

    // All five panels present.
    for (let p = 1; p <= 5; p += 1) {
      expect(document.getElementById(`panel-${p}`)).not.toBeNull();
    }
    // Live toy-code matrices rendered in Panel 1.
    expect(root.querySelectorAll(".matrix-card").length).toBe(3);

    // Encapsulate.
    const encap = document.getElementById("btn-encap") as HTMLButtonElement;
    encap.click();
    await waitFor(() => (document.getElementById("out-encap")?.textContent ?? "").includes("shared secret"));

    // Decapsulate — Patterson should reproduce the secret.
    const decap = document.getElementById("btn-decap") as HTMLButtonElement;
    await waitFor(() => decap.disabled === false);
    decap.click();
    await waitFor(() => (document.getElementById("out-decap")?.textContent ?? "").includes("K_A == K_B"));

    expect(document.getElementById("out-decap")?.textContent).toContain("σ(z)");
    // The σ-root table is rendered when errors were located.
    expect(document.querySelector("#out-decap .sigma-table")).not.toBeNull();
    expect(document.querySelectorAll("#out-decap .sigma-table .row-root").length).toBeGreaterThan(0);
    // AES step unlocks on a successful match (enabled one tick after the
    // success text renders, once deriveAesKey resolves — wait for it).
    const encryptBtn = document.getElementById("btn-encrypt") as HTMLButtonElement;
    await waitFor(() => encryptBtn.disabled === false);
    expect(encryptBtn.disabled).toBe(false);
  });

  it("renders the primer and the S·G·P scramble toggle, and switching views changes the matrix", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    // Newcomer primer defines the four load-bearing terms.
    const primer = document.getElementById("primer-title");
    expect(primer).not.toBeNull();
    const primerText = document.querySelector(".primer")?.textContent ?? "";
    expect(primerText).toContain("Syndrome");
    expect(primerText).toContain("Trapdoor");

    // Scramble view is present with the three real views.
    expect(document.getElementById("scramble-bob")).not.toBeNull();
    const atk = document.getElementById("scramble-atk") as HTMLButtonElement;
    expect(atk).not.toBeNull();

    const figure = document.getElementById("scramble-figure") as HTMLDivElement;
    const structuredHtml = figure.innerHTML;
    // Switching to the attacker's G_pub must change the rendered matrix (it is
    // a different, genuinely-scrambled matrix — not the same grid re-labelled).
    atk.click();
    expect(atk.getAttribute("aria-pressed")).toBe("true");
    expect(figure.innerHTML).not.toBe(structuredHtml);
    expect((document.getElementById("scramble-caption")?.textContent ?? "")).toContain("G");
  });

  it("annotates each Patterson step with a 'why this step' expander", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    (document.getElementById("btn-encap") as HTMLButtonElement).click();
    await waitFor(() => (document.getElementById("out-encap")?.textContent ?? "").includes("shared secret"));
    const decap = document.getElementById("btn-decap") as HTMLButtonElement;
    await waitFor(() => decap.disabled === false);
    decap.click();
    await waitFor(() => (document.getElementById("out-decap")?.textContent ?? "").includes("σ(z)"));

    // At least the syndrome + locator steps carry a why-this-step expander.
    const whys = document.querySelectorAll("#out-decap .pstep-why");
    expect(whys.length).toBeGreaterThanOrEqual(2);
    const whyText = document.querySelector("#out-decap .pstep-why")?.textContent ?? "";
    expect(whyText.toLowerCase()).toContain("why this step");
  });

  it("lets the learner toggle a ciphertext bit, updating weight and aria-pressed", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    (document.getElementById("btn-encap") as HTMLButtonElement).click();
    await waitFor(() => document.querySelector("#out-encap .bit-btn") !== null);

    const weightBefore = Number(document.getElementById("ct-weight")?.textContent);
    // Find a bit that is not currently an error (aria-pressed=false) and click it.
    const fresh = document.querySelector<HTMLButtonElement>('#out-encap .bit-btn[aria-pressed="false"]');
    expect(fresh).not.toBeNull();
    fresh!.click();

    expect(fresh!.getAttribute("aria-pressed")).toBe("true");
    expect(Number(document.getElementById("ct-weight")?.textContent)).toBe(weightBefore + 1);
    // Toggling resets the downstream decapsulate step.
    expect((document.getElementById("btn-encrypt") as HTMLButtonElement).disabled).toBe(true);
  });

  it("uses derived key-size comparisons instead of calling 50 KB a web average", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    const panel = document.getElementById("panel-2")?.textContent ?? "";
    expect(panel).toContain("~221");
    expect(panel).toContain("~888");
    expect(panel).toContain("2.6 times");
    expect(panel).toContain("fixed 100 KB profile-photo example");
    expect(panel).not.toContain("average webpage");
  });

  it("pushes a learner-edited ciphertext beyond t even after all original errors are cleared", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    (document.getElementById("btn-encap") as HTMLButtonElement).click();
    await waitFor(() => document.querySelector("#out-encap .bit-btn") !== null);
    for (const error of Array.from(document.querySelectorAll<HTMLButtonElement>('#out-encap .bit-btn[aria-pressed="true"]'))) {
      error.click();
    }
    expect(document.getElementById("ct-weight")?.textContent).toBe("0");

    (document.getElementById("btn-tamper") as HTMLButtonElement).click();
    expect(document.getElementById("ct-weight")?.textContent).toBe("3");
    expect((document.getElementById("ct-warn") as HTMLParagraphElement).hidden).toBe(false);
    expect(document.getElementById("aria-live-status")?.textContent).toContain("weight 3 exceeds");
  });

  /**
   * Regression. "Exceed correction radius" is the panel's headline lesson, and
   * nothing in this suite used to look at what it renders: the e2e test and the
   * test above both stop at the weight readout, and the toy-kem test only asserts
   * that at least one of thirty tampered runs produced a different secret.
   *
   * What it actually rendered, in every over-radius state, was a confident trace:
   * "Located error positions (roots of σ)", a σ table marking those roots "✓
   * error", "Corrected codeword", and "Recovered message" — all printed
   * unconditionally. A complete census of all 2^16 = 65,536 received vectors says
   * `trace.success` is false for all 30,464 vectors more than t away from a
   * codeword, and that in none of them does the corrected vector land on any
   * codeword at all. Not one of those four labels was true.
   */
  it("does not call a failed decode a corrected codeword or a recovered message", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    const encap = document.getElementById("btn-encap") as HTMLButtonElement;
    const tamper = document.getElementById("btn-tamper") as HTMLButtonElement;
    const decap = document.getElementById("btn-decap") as HTMLButtonElement;

    // "Exceed correction radius" produces a weight-3 vector, and a complete census
    // of all 143,360 (codeword, weight-3 error) pairs says that splits two ways:
    // 57.1% do not decode at all, 42.9% decode onto a DIFFERENT codeword. Both
    // used to be rendered wrong — the first called a non-codeword a "Corrected
    // codeword", the second said "Decoding failed" when Patterson had decoded.
    // Drive until both have been seen; failing to see either is a test failure,
    // not a pass. (At 57/43 the chance of missing one in 40 rounds is ~1e-10.)
    let sawUndecodable = 0;
    let sawWrongCodeword = 0;
    for (let round = 0; round < 40 && (sawUndecodable === 0 || sawWrongCodeword === 0); round += 1) {
      encap.click();
      await waitFor(() => document.querySelector("#out-encap .bit-btn") !== null);
      tamper.click();
      expect(
        document.getElementById("ct-weight")?.textContent,
        "the tamper control must put the ciphertext beyond the correction radius",
      ).toBe("3");

      await waitFor(() => decap.disabled === false);
      decap.click();
      await waitFor(() => (document.getElementById("out-decap")?.textContent ?? "").includes("Result"));
      const text = document.getElementById("out-decap")?.textContent ?? "";
      const rootMarks = Array.from(document.querySelectorAll("#out-decap .sigma-table .row-root td"))
        .map((td) => td.textContent ?? "")
        .join(" ");

      // Whatever happened, an over-radius run must never claim Alice's secret.
      expect(text, "exceeding t must never reproduce the shared secret").not.toContain("K_A == K_B");
      expect((document.getElementById("btn-encrypt") as HTMLButtonElement).disabled).toBe(true);

      if (document.getElementById("decode-failed-note")) {
        sawUndecodable += 1;
        expect(text).toContain("not a codeword");
        expect(text).toContain("Beyond the correction radius");
        expect(text, "a non-codeword must not be labelled a corrected codeword").not.toContain(
          "Corrected codeword",
        );
        expect(text, "bits that were never sent are not a recovered message").not.toContain(
          "Recovered message",
        );
        expect(text, "σ's roots are not located errors when decoding failed").not.toContain(
          "Located error positions",
        );
        expect(rootMarks, "σ roots must not be marked as located errors").not.toContain("✓ error");
      } else {
        sawWrongCodeword += 1;
        // Patterson DID decode here — just onto the wrong codeword. Saying
        // "Decoding failed" would be as wrong as the other branch was.
        expect(text).toContain("Decoded to a different codeword");
        expect(text).not.toContain("Beyond the correction radius");
      }
    }

    expect(
      sawUndecodable,
      "no over-radius run failed to decode, so the failed-decode labelling was never exercised",
    ).toBeGreaterThan(0);
    expect(
      sawWrongCodeword,
      "no over-radius run decoded to a wrong codeword, so that labelling was never exercised",
    ).toBeGreaterThan(0);
  });

  /**
   * Regression: a successful decode must still say all of that. Without this the
   * fix above could be "delete the labels", which would break the lesson instead
   * of correcting it.
   */
  it("still calls a successful decode a corrected codeword and a recovered message", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    (document.getElementById("btn-encap") as HTMLButtonElement).click();
    await waitFor(() => (document.getElementById("out-encap")?.textContent ?? "").includes("shared secret"));
    const decap = document.getElementById("btn-decap") as HTMLButtonElement;
    await waitFor(() => decap.disabled === false);
    decap.click();
    await waitFor(() => (document.getElementById("out-decap")?.textContent ?? "").includes("K_A == K_B"));

    const text = document.getElementById("out-decap")?.textContent ?? "";
    expect(text).toContain("Located error positions");
    expect(text).toContain("Corrected codeword");
    expect(text).toContain("Recovered message");
    expect(text).not.toContain("Beyond the correction radius");
    expect(document.getElementById("decode-failed-note")).toBeNull();
    const rootMarks = Array.from(document.querySelectorAll("#out-decap .sigma-table .row-root td"))
      .map((td) => td.textContent ?? "");
    expect(rootMarks.length, "a successful decode must have located at least one error").toBeGreaterThan(0);
    expect(rootMarks.join(" ")).toContain("✓ error");
  });

  /**
   * Regression: the bar chart announced a floored width as the measurement.
   * Five of the six KEM bars are under 1% of the largest and were all drawn — and
   * all announced — at 2%, so ML-KEM-512 (800 B) and HQC-128 (2,249 B) claimed
   * the same size in the chart whose only job is relative scale.
   */
  it("labels key-size bars with the true proportion, not the minimum bar width", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    const { KEM_PUBLIC_KEY_BENCHMARKS, percentOfMax } = await import("./keysize");
    const max = Math.max(...KEM_PUBLIC_KEY_BENCHMARKS.map((k) => k.bytes));

    // The interesting case must occur: several entries below the 2% floor.
    const belowFloor = KEM_PUBLIC_KEY_BENCHMARKS.filter((k) => (k.bytes / max) * 100 < 2);
    expect(
      belowFloor.length,
      "no bar is below the display floor, so this test proves nothing",
    ).toBeGreaterThan(1);

    const fills = Array.from(document.querySelectorAll<HTMLElement>(".bar-chart .bar-fill"));
    expect(fills.length).toBe(KEM_PUBLIC_KEY_BENCHMARKS.length);

    const labels = fills.map((f) => f.getAttribute("aria-label") ?? "");
    for (const [i, k] of KEM_PUBLIC_KEY_BENCHMARKS.entries()) {
      expect(labels[i], `${k.name} must announce its true proportion`).toContain(percentOfMax(k.bytes, max));
    }

    // Distinct sizes must not announce one identical figure.
    const smallLabels = KEM_PUBLIC_KEY_BENCHMARKS
      .map((k, i) => ({ k, label: labels[i] }))
      .filter(({ k }) => (k.bytes / max) * 100 < 2)
      .map(({ label }) => label);
    expect(
      new Set(smallLabels).size,
      "bars of different sizes must not all announce the same percentage",
    ).toBe(smallLabels.length);
  });

  /**
   * Regression: "46 years" was written into seven places on the page and is now
   * two years stale. It must be computed from 1978, not typed.
   */
  it("computes the years of cryptanalysis rather than hard-coding them", async () => {
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    const expected = new Date().getFullYear() - 1978;
    const page = root.textContent ?? "";
    expect(page).toContain(`${expected} years of cryptanalysis`);
    expect(page).toContain(`Why ${expected} Years Matters`);
    // The comparison table's own column must agree with the prose.
    const cells = Array.from(document.querySelectorAll(".comparison-table tbody tr"))
      .map((tr) => Array.from(tr.querySelectorAll("td")).at(-1)?.textContent ?? "");
    expect(cells[0], "the McEliece row must show the computed span").toBe(`${expected} years`);
    expect(page, "no stale literal may remain").not.toMatch(/\b46 years\b/);
  });

  it("escapes HTML metacharacters in rendered output", async () => {
    // esc() is exercised indirectly; verify decrypted user text is set via textContent.
    const { initUi } = await import("./ui");
    const root = document.createElement("div");
    document.body.appendChild(root);
    await initUi(root);

    const msg = document.getElementById("aes-message") as HTMLTextAreaElement;
    msg.value = "<img src=x onerror=alert(1)>";

    const encap = document.getElementById("btn-encap") as HTMLButtonElement;
    encap.click();
    await waitFor(() => (document.getElementById("out-encap")?.textContent ?? "").includes("shared secret"));
    const decap = document.getElementById("btn-decap") as HTMLButtonElement;
    await waitFor(() => decap.disabled === false);
    decap.click();
    await waitFor(() => !(document.getElementById("btn-encrypt") as HTMLButtonElement).disabled);

    (document.getElementById("btn-encrypt") as HTMLButtonElement).click();
    await waitFor(() => (document.getElementById("out-aes")?.textContent ?? "").includes("IV"));
    (document.getElementById("btn-decrypt") as HTMLButtonElement).click();
    await waitFor(() => (document.getElementById("out-aes")?.textContent ?? "").includes("Decrypted"));

    // The payload must appear as text, never as a live <img> element.
    expect(document.querySelector("#out-aes img")).toBeNull();
    expect(document.getElementById("out-aes")?.textContent).toContain("<img");
  });
});
