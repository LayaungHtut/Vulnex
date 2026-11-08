import { defineConfig } from '@playwright/test';

// The console is built and served by `vite preview`; the API stack (deploy/compose) should be up.
export default defineConfig({
	webServer: {
		command: 'npm run build && npm run preview -- --host 127.0.0.1 --strictPort',
		url: 'http://127.0.0.1:4173/login'
	},
	use: { baseURL: 'http://127.0.0.1:4173' },
	testMatch: '**/*.e2e.{ts,js}'
});
