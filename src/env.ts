import { defineEnvVars } from '@sveltejs/kit/env';

export const variables = defineEnvVars({
	VULNEX_API_URL: {
		description: 'Base URL of the VULNEX control-plane API, called server-side only.',
		schema: (value) => {
			const url = new URL(value || 'http://127.0.0.1:8000'); // throws on a malformed URL at startup
			if (url.protocol !== 'http:' && url.protocol !== 'https:') {
				throw new Error('VULNEX_API_URL must be http(s)');
			}
			return url.href.replace(/\/$/, '');
		}
	}
});
