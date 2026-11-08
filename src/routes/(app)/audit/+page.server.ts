import { ApiError, api } from '#lib/server/api.js';
import { requireSession } from '#lib/server/session.js';
import type { AuditPage } from '#lib/types.js';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url, 'audit.read');
	const before = url.searchParams.get('before');
	const query = before && /^\d{1,18}$/.test(before) ? `?before_id=${before}` : '';
	try {
		const page = await api<AuditPage>(fetch, `/api/v1/audit-events${query}`, {
			token: locals.token
		});
		return { page, paged: Boolean(query), loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return {
			page: { items: [], next_before_id: null },
			paged: Boolean(query),
			loadError: e.detail
		};
	}
};
