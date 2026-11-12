import { test, expect } from '@playwright/test';

// Credentials come from the mock LDAP in docker-compose (glauth).
const USER = process.env.E2E_USER ?? 'alice';
const PASS = process.env.E2E_PASSWORD ?? 'alice_password';

test.describe('login flow', () => {
  test('login, dashboard, silent refresh after reload, logout', async ({ page, context }) => {
    await page.goto('/login');
    await page.getByLabel('Имя пользователя').fill(USER);
    await page.getByLabel('Пароль', { exact: true }).fill(PASS);
    await page.getByRole('button', { name: 'Войти' }).click();

    // F-05: dashboard with the user profile
    await expect(page.getByText('Мой профиль')).toBeVisible();

    // Refresh token must not leak into web storage (acceptance #9).
    const storage = await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    }));
    expect(storage.local).toBe(0);
    expect(storage.session).toBe(0);

    // HttpOnly cookie present (invisible to document.cookie but sent).
    const cookies = await context.cookies();
    expect(cookies.some((c) => c.name === 'aps_refresh' && c.httpOnly)).toBe(true);

    // F-15 acceptance #5: silent refresh keeps the session after reload.
    await page.reload();
    await expect(page.getByText('Мой профиль')).toBeVisible();

    // Logout returns to the login page.
    await page.getByRole('button', { name: 'Выйти' }).click();
    await expect(page).toHaveURL(/\/login/);
  });

  test('wrong password shows generic error (S-08)', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Имя пользователя').fill(USER);
    await page.getByLabel('Пароль', { exact: true }).fill('totally-wrong');
    await page.getByRole('button', { name: 'Войти' }).click();
    await expect(page.getByText('Неверное имя пользователя или пароль')).toBeVisible();
  });
});
