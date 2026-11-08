import { expect, test } from '@playwright/test';

test('status page reports the API state', async ({ page }) => {
	await page.goto('/');
	await expect(page.getByRole('heading', { name: 'VULNEX console' })).toBeVisible();
	// Either outcome is a real reading; the e2e run does not assume the API is up.
	await expect(page.getByText(/Operational|Degraded|Unreachable/)).toBeVisible();
});
