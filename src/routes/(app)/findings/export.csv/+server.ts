import { error } from '@sveltejs/kit';
import { VULNEX_API_URL } from '$app/env/private';
import { findingQuery, requireFindings } from '../filters.js';
import type { RequestHandler } from './$types';

// The browser never holds the API token, so the console streams the API's CSV through.
export const GET: RequestHandler = async ({ fetch, locals, url }) => {
	requireFindings(locals, url);
	const query = findingQuery(url);
	for (const k of ['band', 'assignee', 'kev', 'q', 'sort', 'offset']) query.delete(k);
	const res = await fetch(`${VULNEX_API_URL}/api/v1/findings/export.csv?${query}`, {
		headers: { authorization: `Bearer ${locals.token}` },
		signal: AbortSignal.timeout(30_000)
	}).catch(() => null);
	if (!res?.ok || !res.body)
		error(res?.status && res.status < 500 ? res.status : 503, 'Export failed');
	return new Response(res.body, {
		headers: {
			'content-type': 'text/csv; charset=utf-8',
			'content-disposition': 'attachment; filename="vulnex-findings.csv"',
			'cache-control': 'no-store'
		}
	});
};
