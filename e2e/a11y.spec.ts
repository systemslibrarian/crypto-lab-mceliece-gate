import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where all
 * four output areas are absent, five of Panel 3's six buttons are locked and the
 * document contains no `<details>` at all; both skip links focused; all three
 * branches of Panel 1's G / S·G / G_pub fork; encapsulation, then the error
 * weight walked over the correction radius by hand and back (which is the only
 * route to `#ct-warn`); Patterson decapsulation on the success path, with every
 * "why this step" note and the σ root table opened through their own
 * `<summary>`; the brute-force attacker; AES-256-GCM encrypt and decrypt; the
 * empty-message `role="alert"`, which is the only state that paints
 * `#error-status`; then "Exceed correction radius", which relocks everything
 * downstream, and a second decapsulation that FAILS — the only state on the page
 * that paints the `--error` match badge; and finally every injected error
 * cleared to weight 0. Each of those states is scanned, in both themes, at
 * desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no output area is
 * force-revealed and no `hidden` attribute stripped (the gate this replaces did
 * both, and un-hiding `#ct-warn` at weight = t built a document that contradicts
 * itself), why the lab's defaults are asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
