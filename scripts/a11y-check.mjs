// Accessibility + responsive audit: axe-core WCAG 2.1 AA scan at mobile
// (320px) and desktop widths, plus screenshots of the interactive flow.
// Run against `vite preview` (see npm run a11y).
import { chromium } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";
import { mkdirSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/* Own the server this audit runs against.
 *
 * The header says "Run against `vite preview`", and nothing started one: the
 * default pointed at 4706, which the fleet registry
 * (crypto-lab/tools/playwright-ports.json) assigns to no lab, so `npm run a11y`
 * died on connection-refused and reported no accessibility at all. An audit
 * aimed at a port nothing serves is not a weak gate; it is an absent one that
 * reads as present.
 *
 * PREVIEW_URL still points this at an already-running server. With it unset
 * this builds if needed, starts its own preview on 4232 -- this lab's own port
 * -- with --strictPort, and stops it by its own pid, never by pattern.
 */
const OWN_PORT = 4232;
const BASE = process.env.PREVIEW_URL ?? `http://localhost:${OWN_PORT}/crypto-lab-mceliece-gate/`;
let ownServer = null;

async function reachable(u) {
  try {
    return (await fetch(u, { redirect: "follow" })).ok;
  } catch {
    return false;
  }
}

async function startOwnServer() {
  if (!existsSync(join(REPO_ROOT, "dist", "index.html"))) {
    const built = spawnSync("npm", ["run", "build"], { cwd: REPO_ROOT, encoding: "utf8" });
    if (built.status !== 0) {
      console.error("FAIL: could not build before starting the preview server");
      console.error((built.stdout ?? "") + (built.stderr ?? ""));
      process.exit(1);
    }
  }
  const child = spawn("npm", ["run", "preview", "--", "--port", String(OWN_PORT), "--strictPort"], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  for (let i = 0; i < 60; i++) {
    if (await reachable(BASE)) return child;
    if (child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL: preview did not come up on port ${OWN_PORT} within 30s.`);
  console.error("      --strictPort does not move, so this is a port collision or a build fault:");
  console.error(log.trim() || "      (the server printed nothing)");
  try {
    if (child.exitCode === null) process.kill(child.pid);
  } catch {
    /* already gone */
  }
  process.exit(1);
}

/* By pid, and only the child this process started -- never by pattern. */
function stopOwnServer() {
  if (ownServer?.exitCode === null) {
    try {
      process.kill(ownServer.pid);
    } catch {
      /* already gone */
    }
  }
}

if (!process.env.PREVIEW_URL) ownServer = await startOwnServer();


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
stopOwnServer();

console.log(`\nScreenshots written to ${OUT}`);
console.log(totalSerious === 0
  ? "✅ No serious/critical WCAG violations."
  : `❌ ${totalSerious} serious/critical violation group(s).`);
process.exit(totalSerious === 0 ? 0 : 1);
