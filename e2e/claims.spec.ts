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
