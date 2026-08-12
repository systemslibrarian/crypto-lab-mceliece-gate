import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Six rules govern everything here, and every one of them is a correction of
 * the gate this replaces (`e2e/a11y.spec.ts`, whose whole drive was one
 * `revealAll()` helper):
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `revealAll()` pushed
 *     `transition:none!important; animation:none!important` through
 *     `addStyleTag`. That BYPASSED `styles/main.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     On this page the block is small — it clamps every duration to 0.01ms and
 *     cancels `.bar-fill`'s 0.5s width transition — but "small" is a
 *     measurement, not an assumption, and the injection could not tell the
 *     difference between a block that works and one that does not exist.
 *     `boot` asks for the preference and ASSERTS it took effect instead.
 *
 *     The reduced-motion block was checked for the defect where cancelling an
 *     animation strands an element at its start value. It cannot occur here:
 *     `styles/main.css` declares no `@keyframes` and no `animation` property at
 *     all, so nothing on this page reaches its visible state by animating into
 *     it. `expectNotBlank` measures that in every state rather than trusting the
 *     reading.
 *
 *  2. IT FORCE-REVEALED EVERY PANEL, AND BUILT A DOCUMENT THAT CONTRADICTS
 *     ITSELF. The same `addStyleTag` carried `.output-area{display:block!important}`,
 *     and the script that followed added `.visible` to all four output areas,
 *     set `open = true` on every `<details>`, and stripped `hidden` from every
 *     element that had one. Only Panel 3's encapsulate/decapsulate pair was ever
 *     run, so `#out-attack` and `#out-aes` were revealed EMPTY — and worse, the
 *     `hidden` strip un-hid `#ct-warn`, the "error weight exceeds t" warning, in
 *     a state where the error weight is exactly t. That is a page telling the
 *     reader the ciphertext is undecodable while the badge beside it says the
 *     shared secrets match. No visitor can load it, and no assertion about it
 *     describes this lab. This gate never touches `display`, `open` or `hidden`;
 *     every output area is revealed by the button that fills it, and every
 *     disclosure is opened by clicking its own `<summary>`.
 *
 *  3. `if (await encap.count())` GUARDED THE ENTIRE DRIVE. If `#btn-encap` ever
 *     stopped rendering — the single most likely way this lab breaks, since
 *     `initPanel3` returns early and silently when any one of its six buttons is
 *     missing — the guard skipped the drive and the gate went green on a page
 *     with no working exhibit. Here every control is asserted present and
 *     enabled before it is used.
 *
 *  4. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE. Every state the
 *     drive built was overwritten before anything measured it, and the 380px
 *     column had never been scanned at all. This drive scans after every single
 *     step, in {dark, light} × {1280, 380}.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. See `scan`. On this page a
 *     violations-only assertion missed sixteen real findings on first paint
 *     alone: `aria-label` is PROHIBITED on a role-less `<div>`/`<span>`/`<p>`
 *     and axe files it under `incomplete`, never under `violations`.
 *
 *  6. IT HAD NO REFLOW, KEYBOARD-SCROLLER OR NON-TEXT-CONTRAST ORACLE, and this
 *     page needs all three: a `min-width: 720px` comparison table, three
 *     `overflow-x: auto` matrix `<pre>` blocks, an `overflow-x: auto` matrix
 *     grid, and a palette whose `--border-strong` control-boundary token was
 *     applied to exactly one resting control.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `styles/main.css` contains no
 * `@keyframes` and no `animation` property, and its only two `opacity`
 * declarations are `.cl-hero-sub { opacity: .85 }` and `.btn:disabled
 * { opacity: .45 }` — neither of which is ever zero, and the second of which is
 * on an inactive component WCAG 1.4.3 exempts. The check runs in every state
 * regardless, because all of those are properties of the current stylesheet
 * rather than of the page, and this is the cheapest place to catch the first
 * exception.
 *
 * `aria-hidden` subtrees are excluded, which on this page means the three
 * `<pre>` matrix dumps, the per-bit `<span>`s inside every `.bit-vector`, the
 * `.step-number` badges and the header/footer SVG glyphs. Each was checked by
 * hand: none carries a value that is not also stated in exposed text beside it.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. That is a live risk here: `src/main.ts` catches a failed `initUi` and
 * replaces the whole app with one `role="alert"` paragraph, which is a perfectly
 * accessible document and tells you nothing about the lab. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * Unlike most labs in this fleet this page really does depend on the demotion
 * running. `index.html`'s `dedupeBanner()` looks for a `<header>` that is not
 * scoped inside sectioning content, and `renderHeader()` emits
 * `<header class="cl-hero">` as a child of `.app-container`, which is a plain
 * `<div>` inside `#app`, another plain `<div>` — so `closest('main, article,
 * aside, nav, section')` finds nothing and the hero IS an implicit banner until
 * the script rewrites it to `role="group"`. Asserting the OUTCOME rather than
 * either mechanism means a change to the nesting is caught too.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** The four output areas that ship behind `.output-area { display: none }`. */
export const OUTPUT_AREAS = ['#out-encap', '#out-decap', '#out-attack', '#out-aes'] as const;

/** The five controls that ship DISABLED until a prerequisite has been run. */
export const LOCKED_CONTROLS = [
  '#btn-tamper',
  '#btn-decap',
  '#btn-attack',
  '#btn-encrypt',
  '#btn-decrypt',
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')`, the shared bar's `#cl-theme-toggle`
 * writes `localStorage.setItem('theme', …)`, and this lab's own `#theme-toggle`
 * (hidden by the shared bar's CSS, but still wired) writes the same key. If any
 * of the three drifted apart the theme would silently stop persisting, and this
 * boot fails on `data-theme` rather than quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab ships almost entirely
 * EMPTY below Panel 2: all four `.output-area` panels are behind
 * `display: none`, five of Panel 3's six buttons ship `disabled`, and there is
 * not a single `<details>` element in the document — every disclosure this page
 * has is created by the decapsulation renderer. That is a real state, it is the
 * first one every reader sees, and the gate this replaces never scanned it.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // `initUi` builds the whole document; a navigation that resolves proves
  // nothing. Panel 2's key generation is awaited inside it, so the status line
  // reaching its final text is the signal that mount finished.
  await expect(page.locator('#aria-live-status')).toHaveText(
    'Public key generated: 261,120 bytes.'
  );
  await expect(page.locator('#pk-hex')).not.toHaveValue('Generating…');

  // ── Everything Panel 3 generates ships absent ────────────────────────────
  for (const sel of OUTPUT_AREAS) await expect(page.locator(sel)).toBeHidden();
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();
  await expect(page.locator('#btn-encap')).toBeEnabled();
  await expect(page.locator('#error-status')).toBeEmpty();

  // Every `<details>` on this page is minted by the decapsulation renderer, so
  // the arrival document has none at all. The gate this replaces set
  // `open = true` on "every <details>" — a loop that, at the only moment it ran
  // on the arrival state, had nothing to iterate.
  await expect(page.locator('details')).toHaveCount(0);

  // ── Panel 1's three-way fork ships on its first branch ───────────────────
  await expect(page.locator('#scramble-bob')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#scramble-mixed')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#scramble-atk')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#scramble-caption')).toContainText('Structured G (8×16)');

  // ── The one editable input, at its shipped value ─────────────────────────
  await expect(page.locator('#aes-message')).toHaveValue(
    'Classic McEliece: conservative post-quantum security since 1978.'
  );

  // `[hidden]` has specificity (0,1,0) — identical to a class — so any later
  // `.foo { display: … }` beats it and the attribute silently does nothing.
  // Seven labs in this fleet had exactly that. Measured here rather than
  // inferred from the CSS, because `#ct-warn`'s hidden state is the ONLY thing
  // separating "this ciphertext is decodable" from "it is not".
  expect(
    await page.evaluate(() => {
      const el = document.querySelector('.panel-note');
      if (!el) return 'no probe element';
      el.setAttribute('hidden', '');
      const d = getComputedStyle(el).display;
      el.removeAttribute('hidden');
      return d;
    }),
    'the [hidden] attribute must actually hide — no later class may out-rank it'
  ).toBe('none');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is
 * the shape that breaks it: an eight-column comparison table carrying a hard
 * `min-width: 720px`, three `<pre>` blocks holding raw binary matrices, a
 * 16-column bit grid per matrix view, and an 8 KB hex dump. Each wide thing is
 * meant to scroll inside its own container; the assertion here is that none of
 * them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.table-wrap`, every `.matrix-card pre` and every
    // `.mgrid`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab has four kinds of scroller and handles two of them: `.table-wrap`
 * ships `role="region" tabindex="0"`, and `.mgrid` ships `role="img"
 * tabindex="0"`. The other two are `.matrix-card pre` (`overflow-x: auto`, three
 * of them, `aria-hidden` and with no tabindex) and the `.hex-dump` textarea
 * (focusable by virtue of being a form control). Whether the `<pre>` blocks
 * actually overflow depends on the viewport and on the toy code's dimensions,
 * which is exactly why this is measured in every state at both widths rather
 * than reasoned about once.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * This wrapper is the repair of a dead oracle rather than a refactor. In the
 * reference gate every other lab in this fleet was copied from,
 * `expectNoNewNonTextFailures` was reachable only from inside
 * `expectScrollersReachableSoft`, AFTER that function's
 * `if (!COLLECTING) return …` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos carried an empty
 * `nontext-baseline.ts` that was not a clean bill of health but the footprint of
 * a check that had never looked. It is called from `scan()` here.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. This page has both kinds live — every `<button>` in Panel 3 and Panel 1,
 * and the `.timeline::before` rail plus the `.timeline-item::before` dots that
 * are the entire visual structure of Panel 5.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`
      );
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides. On this page that bucket held
 *    SIXTEEN nodes on first paint (the chip strip, the matrix grid, the size
 *    grid and each of its cards, the use-case grid, all six recommendation tags
 *    and the footer's related-demos paragraph), and not one of them ever reached
 *    the violations array the old gate asserted on.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    which also settles the six `color-contrast` cells axe declines to judge in
 *    the comparison table.
 *  - non-text contrast and generated content — SC 1.4.11, which axe has no rule
 *    for; see `expectNoNewNonTextFailures`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the exact shape they catch: a shared sticky `<header role="banner">` above a
  // hero `<header>` that `dedupeBanner()` has to demote at runtime, with an
  // `<aside role="complementary">` inside that hero.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 20),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open every VISIBLE shut disclosure by clicking its summary.
 *
 * There is no `<details>` on this page until decapsulation has run: the three or
 * four `.pstep-why` annotations and the `.sigma-details` root table are all
 * minted by the Patterson renderer. `:visible` is load-bearing because
 * `.sigma-details` only exists when σ actually had roots, and every one of them
 * lives inside `#out-decap`, which is `display: none` until that same run.
 */
async function openAllDisclosures(page: Page): Promise<number> {
  const shut = page.locator('details:not([open]) > summary:visible');
  let opened = 0;
  for (let i = await shut.count(); i > 0 && opened < 40; i = await shut.count()) {
    await shut.first().click();
    opened += 1;
  }
  await expect(page.locator('details:not([open]) > summary:visible')).toHaveCount(0);
  return opened;
}

/** Current error weight, read from the live readout the lab maintains. */
async function weight(page: Page): Promise<number> {
  return Number(await page.locator('#ct-weight').textContent());
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - IT STARTS EMPTY, AND THE EMPTY STATE IS SCANNED FIRST. All four output
 *    areas ship `display: none`, five of Panel 3's six buttons ship `disabled`,
 *    and the document contains no `<details>` at all. The gate this replaces
 *    forced every one of those open before its single scan, so it never measured
 *    the state a reader arrives in.
 *
 *  - EVERY PREREQUISITE IS SCANNED BEFORE ITS UNLOCK. Each locked control is
 *    asserted disabled, the control that unlocks it is pressed, and it is then
 *    asserted enabled — so the "before" rendering, which is what a reader meets,
 *    is measured as well as the "after".
 *
 *  - BOTH OUTCOMES OF EVERY FORK. Panel 1's generator view has three branches
 *    and all three are driven. Panel 3's decapsulation has two: the success path
 *    (`.match-badge.success`, `--success` ink on `--success-bg`) and the
 *    over-radius failure path (`.match-badge.fail`, `--error` on `--error-bg`) —
 *    two whole inks that no other state on the page paints. The brute-force
 *    attacker has the same two outcomes. The AES step has a third state the
 *    happy path never reaches: `#error-status`, a `role="alert"` painted in
 *    `--error` directly on the panel, which only appears when Encrypt is pressed
 *    with an empty message.
 *
 *  - THE ERROR-WEIGHT EXTREMES, NOT JUST THE DEFAULT. `#ct-warn` is `hidden`
 *    while the weight is ≤ t and shown above it, and the ciphertext bit buttons
 *    are the only route between those states. The drive walks the weight up past
 *    t by hand, back down, and all the way to zero, and uses
 *    "Exceed correction radius" as well — which is a different code path
 *    (`btn-tamper` tops the weight up to exactly t+1 from wherever it is).
 *
 *  - NO FIXED TIMEOUTS. Every step here has a DOM completion signal: an output
 *    area becoming visible, a button returning from `disabled`, a readout
 *    changing value, the status line changing text. The drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, all four output areas absent and five controls locked');

  // This page carries TWO skip links, and only the first is where a skip link
  // is supposed to be. The shared bar's `.cl-skip-link` (→ `#app`) is the first
  // focusable element in the document. The lab's own `.skip-link`
  // (→ `#main-content`) sits AFTER the whole `.cl-topbar`, so it is the SIXTH
  // tab stop — behind the brand link, Menu, GitHub and the theme toggle. It
  // therefore bypasses nothing a reader has not already tabbed through. Both are
  // real states a keyboard reader lands on, and both are scanned; the count is
  // asserted rather than assumed so the day either moves, this fails loudly
  // instead of silently scanning the wrong element.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused (tab stop 1)');
  for (let i = 0; i < 5; i++) await page.keyboard.press('Tab');
  await expect(page.locator('a.skip-link')).toBeFocused();
  await scanAt("the lab's own skip link focused (tab stop 6)");

  // ── Panel 1: all three branches of the S·G·P fork ───────────────────────
  await page.click('#scramble-mixed');
  await expect(page.locator('#scramble-mixed')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#scramble-caption')).toContainText('S · G (rows mixed)');
  await scanAt('generator view: S · G, rows mixed');

  await page.click('#scramble-atk');
  await expect(page.locator('#scramble-atk')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#scramble-caption')).toContainText('shuffled the columns');
  await scanAt('generator view: G_pub as the attacker sees it');

  await page.click('#scramble-bob');
  await expect(page.locator('#scramble-bob')).toHaveAttribute('aria-pressed', 'true');
  await scanAt('generator view: back to the structured G');

  // ── Panel 3, step 1: encapsulate ────────────────────────────────────────
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();
  await page.click('#btn-encap');
  await expect(page.locator('#out-encap')).toBeVisible();
  await expect(page.locator('#out-encap .bit-btn')).toHaveCount(16);
  await expect(page.locator('#btn-tamper')).toBeEnabled();
  await expect(page.locator('#btn-decap')).toBeEnabled();
  await expect(page.locator('#ct-warn')).toBeHidden();
  expect(await weight(page), 'a fresh encapsulation carries exactly t errors').toBe(2);
  await scanAt('encapsulated: message, codeword, editable ciphertext, weight = t');

  // ── The over-radius warning, reached the way a reader reaches it ─────────
  const clean = page.locator('#out-encap .bit-btn[aria-pressed="false"]').first();
  const flipped = await clean.getAttribute('data-bit');
  await clean.click();
  await expect(page.locator('#ct-warn')).toBeVisible();
  expect(await weight(page), 'flipping a clean bit must push the weight over t').toBe(3);
  await scanAt('one bit flipped by hand, error weight over the correction radius');

  // Back down, which also proves the warning is genuinely reactive rather than
  // one-way — the failure mode the old gate manufactured by stripping `hidden`.
  //
  // It has to be the SAME bit, not merely any bit that is currently in error.
  // The shared secret is SHA-256(m ‖ e), so an error SET of the right size but
  // the wrong membership decodes perfectly and still yields a different secret:
  // clearing one of Alice's own errors instead lands on `.match-badge.fail`
  // through the success path, and the next assertion would fail for a reason
  // that has nothing to do with accessibility. (That is correct lab behaviour,
  // not a defect — it is what the exhibit is for.)
  await page.click(`#out-encap .bit-btn[data-bit="${flipped}"]`);
  await expect(page.locator('#ct-warn')).toBeHidden();
  expect(await weight(page)).toBe(2);
  await scanAt('the same bit cleared again, back inside the correction radius');

  // ── Panel 3, step 2: decapsulate, the SUCCESS path ──────────────────────
  await expect(page.locator('#btn-attack')).toBeDisabled();
  await expect(page.locator('#btn-encrypt')).toBeDisabled();
  await page.click('#btn-decap');
  await expect(page.locator('#out-decap')).toBeVisible();
  await expect(page.locator('#out-decap .match-badge.success')).toBeVisible();
  await expect(page.locator('#btn-attack')).toBeEnabled();
  await expect(page.locator('#btn-encrypt')).toBeEnabled();
  await scanAt('Patterson decoded, K_A == K_B, every disclosure still shut');

  // The disclosures this page has exist only now.
  const opened = await openAllDisclosures(page);
  expect(opened, 'the Patterson trace must mint the "why this step" disclosures').toBeGreaterThan(
    0
  );
  await expect(page.locator('.sigma-details[open] .sigma-table .row-root')).toHaveCount(2);
  await scanAt('every "why this step" note and the σ root table open');

  // ── Panel 3, step 3: the attacker, SUCCESS path ─────────────────────────
  await page.click('#btn-attack');
  await expect(page.locator('#out-attack')).toBeVisible();
  await expect(page.locator('#out-attack')).toContainText('Brute force found');
  await scanAt('brute-force syndrome decoding found the error pattern');

  // ── Panel 3, step 4: AES-256-GCM, both halves ───────────────────────────
  await expect(page.locator('#btn-decrypt')).toBeDisabled();
  await page.click('#btn-encrypt');
  await expect(page.locator('#out-aes')).toBeVisible();
  await expect(page.locator('#out-aes')).toContainText('Ciphertext length:');
  await expect(page.locator('#btn-decrypt')).toBeEnabled();
  await scanAt('message encrypted under the recovered shared secret');

  await page.click('#btn-decrypt');
  await expect(page.locator('#out-aes')).toContainText('Decrypted:');
  await scanAt('full KEM + DEM round-trip, plaintext recovered');

  // ── The empty-message error state ───────────────────────────────────────
  // `#error-status` is a role="alert" painted in --error directly on the panel
  // surface, and this is the only route to it.
  await page.fill('#aes-message', '');
  await page.click('#btn-encrypt');
  await expect(page.locator('#error-status')).toHaveText('Enter a message to encrypt.');
  await scanAt('empty-message alert, the only state that paints #error-status');
  await page.fill('#aes-message', 'restored');
  await page.click('#btn-encrypt');
  await expect(page.locator('#error-status')).toBeEmpty();
  await expect(page.locator('#out-aes')).toContainText('Ciphertext length:');
  await scanAt('alert cleared by a successful re-encrypt');

  // ── The tamper path: over the radius, and everything downstream relocks ──
  await page.click('#btn-tamper');
  await expect(page.locator('#ct-warn')).toBeVisible();
  expect(await weight(page), 'the tamper control tops the weight up to exactly t+1').toBe(3);
  await expect(page.locator('#btn-attack')).toBeDisabled();
  await expect(page.locator('#btn-encrypt')).toBeDisabled();
  await expect(page.locator('#btn-decrypt')).toBeDisabled();
  await expect(page.locator('#out-decap')).toBeHidden();
  await expect(page.locator('#out-aes')).toBeHidden();
  await scanAt('ciphertext tampered past t, decap/attack/AES output cleared and relocked');

  // ── Decapsulate again: the FAILURE path ─────────────────────────────────
  await page.click('#btn-decap');
  await expect(page.locator('#out-decap')).toBeVisible();
  await expect(page.locator('#out-decap .match-badge.fail')).toBeVisible();
  await expect(page.locator('#btn-encrypt')).toBeDisabled();
  await scanAt('over-radius decapsulation failed — the --error badge, its only state');

  await page.click('#btn-attack');
  await expect(page.locator('#out-attack')).toBeVisible();
  await scanAt('brute force against the tampered ciphertext');

  // ── All errors cleared by hand: weight 0, a clean codeword ──────────────
  const errs = page.locator('#out-encap .bit-btn[aria-pressed="true"]');
  for (let n = await errs.count(); n > 0; n = await errs.count()) await errs.first().click();
  expect(await weight(page)).toBe(0);
  await expect(page.locator('#ct-warn')).toBeHidden();
  await scanAt('every injected error cleared by hand, weight 0');

  await page.click('#btn-decap');
  await expect(page.locator('#out-decap .match-badge')).toBeVisible();
  await openAllDisclosures(page);
  await scanAt('final decode of the error-free ciphertext, page fully populated');
}
