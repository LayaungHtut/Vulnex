import { ApiError, api } from '#lib/server/api.js';
import type { FindingPage } from '#lib/types.js';
import { findingQuery, requireFindings } from './filters.js';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireFindings(locals, url);
	const query = findingQuery(url);
	query.set('limit', '50');
	try {
		const page = await api<FindingPage>(fetch, `/api/v1/findings?${query}`, {
			token: locals.token
		});
		return { page, query: query.toString(), loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return { page: { items: [], total: 0 } as FindingPage, query: '', loadError: e.detail };
	}
};
