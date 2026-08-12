import { expect, test } from '@playwright/test';

test('key-size prose is derived from named fixed examples', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#panel-2');
  await expect(panel).toContainText('~221');
  await expect(panel).toContainText('~888');
  await expect(panel).toContainText('2.6 times');
  await expect(panel).toContainText('fixed 100 KB profile-photo example');
  await expect(panel).not.toContainText('average webpage');
});

/**
 * Regression: Panel 3's opening paragraph said flatly "An attacker cannot."
 * Step 3 of the same panel, one click away, recovers the error vector by brute
 * force — a complete census says it succeeds on all 30,720 distance-2
 * ciphertexts, i.e. every ordinary encapsulation this demo produces. The page
 * must not assert impossibility where its own exhibit demonstrates success; the
 * claim it can support is about cost at real parameters.
 */
test('the intro does not claim impossibility that step 3 refutes on the same page', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#panel-3');
  await expect(panel).not.toContainText('An attacker cannot');

  await page.locator('#btn-encap').click();
  await expect(page.locator('#out-encap .bit-btn')).not.toHaveCount(0);
  await page.locator('#btn-decap').click();
  await expect(page.locator('#out-decap')).toContainText('K_A == K_B');

  // The attacker step must actually succeed at toy size — that is the whole point.
  await page.locator('#btn-attack').click();
  await expect(page.locator('#out-attack')).toContainText('Brute force found');

  // ...and the intro must already have said so rather than denying it.
  await expect(panel.locator('p').first()).toContainText('has to search');

  // The real-parameter figure must be labelled a search space, not a security level.
  await expect(page.locator('#out-attack')).toContainText(
    'size of the haystack, not the cost of the attack',
  );
  await expect(page.locator('#out-attack')).toContainText('information-set decoding');
});

/**
 * Regression: five of the six KEM bars are under 1% of the largest, were drawn at
 * the 2% minimum width, and announced that floor as the measurement — so
 * ML-KEM-512 (800 B) and HQC-128 (2,249 B) claimed the same size in the chart
 * whose only job is relative scale.
 */
test('key-size bars announce true proportions, not the minimum bar width', async ({ page }) => {
  await page.goto('.');
  const fills = page.locator('.bar-chart .bar-fill');
  const n = await fills.count();
  expect(n).toBeGreaterThan(1);

  const labels: string[] = [];
  for (let i = 0; i < n; i += 1) labels.push((await fills.nth(i).getAttribute('aria-label')) ?? '');

  const sub = labels.filter((l) => !l.startsWith('100%'));
  expect(sub.length, 'the small bars must exist for this to check anything').toBeGreaterThan(1);
  expect(new Set(sub).size, 'distinct key sizes must not announce one figure').toBe(sub.length);
  for (const l of sub) expect(l, 'no sub-1% bar may announce a whole 2%').not.toMatch(/^2% /);
});

test('tamper control guarantees an over-radius state after learner edits', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-encap').click();
  await expect(page.locator('#out-encap .bit-btn')).not.toHaveCount(0);

  const errors = page.locator('#out-encap .bit-btn[aria-pressed="true"]');
  while (await errors.count()) await errors.first().click();
  await expect(page.locator('#ct-weight')).toHaveText('0');

  await page.locator('#btn-tamper').click();
  await expect(page.locator('#ct-weight')).toHaveText('3');
  await expect(page.locator('#ct-warn')).toBeVisible();
  await expect(page.locator('#aria-live-status')).toContainText('weight 3 exceeds the correction radius t = 2');
});
