// Accessibility + responsive audit: axe-core WCAG 2.1 AA scan at mobile
// (320px) and desktop widths, plus screenshots of the interactive flow.
// Run against `vite preview` (see npm run a11y).
import { chromium } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";
import { mkdirSync } from "node:fs";

const BASE = process.env.PREVIEW_URL ?? "http://localhost:4173/crypto-lab-mceliece-gate/";
const OUT = new URL("../.a11y/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
mkdirSync(OUT, { recursive: true });

const VIEWPORTS = [
  { name: "mobile-320", width: 320, height: 720 },
  { name: "desktop-1280", width: 1280, height: 900 }
];

const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

const summarize = (violations) =>
  violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, help: v.help }));

let totalSerious = 0;
const report = [];

const browser = await chromium.launch();
try {
  for (const vp of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
    const page = await ctx.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.waitForSelector("#panel-1");

    // Static scan.
    const staticScan = await new AxeBuilder({ page }).withTags(WCAG).analyze();
    await page.screenshot({ path: `${OUT}/${vp.name}-initial.png`, fullPage: true });

    // Drive the interactive flow.
    await page.click("#btn-encap");
    await page.waitForSelector("#out-encap .bit-btn");
    await page.click("#btn-decap");
    await page.waitForFunction(() =>
      (document.getElementById("out-decap")?.textContent ?? "").includes("K_A == K_B")
    );
    // Expand the σ-root table so it is in the screenshot + scan.
    await page.click("#out-decap .sigma-details summary").catch(() => {});
    await page.screenshot({ path: `${OUT}/${vp.name}-decoded.png`, fullPage: true });

    // Dynamic scan (after content is rendered).
    const dynamicScan = await new AxeBuilder({ page }).withTags(WCAG).analyze();

    const violations = [...staticScan.violations, ...dynamicScan.violations];
    const serious = violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    totalSerious += serious.length;
    report.push({ viewport: vp.name, violations: summarize(violations) });

    // Horizontal-overflow check (mobile must not scroll sideways).
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    );
    report.push({ viewport: vp.name, horizontalOverflowPx: overflow });

    await ctx.close();
  }
} finally {
  await browser.close();
}

console.log(JSON.stringify(report, null, 2));
console.log(`\nScreenshots written to ${OUT}`);
console.log(totalSerious === 0
  ? "✅ No serious/critical WCAG violations."
  : `❌ ${totalSerious} serious/critical violation group(s).`);
process.exit(totalSerious === 0 ? 0 : 1);
