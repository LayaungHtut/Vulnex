import { ApiError, api } from '#lib/server/api.js';
import { requireSession } from '#lib/server/session.js';
import type { ScanPage } from '#lib/types.js';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url, 'scans.read');
	try {
		const page = await api<ScanPage>(fetch, '/api/v1/scans?limit=100', { token: locals.token });
		return { page, loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return { page: { items: [], total: 0 } as ScanPage, loadError: e.detail };
	}
};
