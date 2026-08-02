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
