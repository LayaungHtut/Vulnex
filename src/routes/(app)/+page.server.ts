import { VULNEX_API_URL } from '$app/env/private';
import { requireSession } from '#lib/server/session.js';
import type { PageServerLoad } from './$types';

export type ApiStatus =
	| { state: 'ready'; version: string }
	| { state: 'unavailable'; detail: string }
	| { state: 'unreachable' };

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url);
	let api: ApiStatus;
	try {
		// Must exceed the API's own DB connect timeout (3 s, ~4 s measured), or a database outage
		// is misreported as the API being unreachable.
		const res = await fetch(`${VULNEX_API_URL}/readyz`, { signal: AbortSignal.timeout(8000) });
		const body = await res.json();
		api = res.ok
			? { state: 'ready', version: String(body.version) }
			: { state: 'unavailable', detail: String(body.detail ?? res.statusText) };
	} catch {
		api = { state: 'unreachable' };
	}
	return { api, checkedAt: new Date().toISOString() };
};
