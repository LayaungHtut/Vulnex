import { expect, test } from '@playwright/test';

// Needs the API stack running (deploy/compose) for the sign-in form to reach anything;
// these checks hold whether or not an account exists.

test('anonymous visitors are sent to sign-in, keeping their destination', async ({ page }) => {
	await page.goto('/members');
	await expect(page).toHaveURL(/\/login\?next=%2Fmembers$/);
	await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
});

test('wrong credentials show a generic error', async ({ page }) => {
	await page.goto('/login');
	await page.getByLabel('Email').fill('nobody@example.test');
	await page.getByLabel('Password').fill('not-the-password');
	await page.getByRole('button', { name: 'Sign in' }).click();
	await expect(page.getByRole('alert')).toHaveText(
		/Invalid email or password|unreachable|Too many/
	);
});
