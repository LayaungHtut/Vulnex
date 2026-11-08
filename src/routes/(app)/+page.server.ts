import { VULNEX_API_URL } from '$app/env/private';
import { ApiError, api } from '#lib/server/api.js';
import { requireSession } from '#lib/server/session.js';
import {
	can,
	type AssetPage,
	type FindingSummary,
	type IntelSource,
	type ScanPage
} from '#lib/types.js';
import type { PageServerLoad } from './$types';

export type ApiStatus =
	| { state: 'ready'; version: string }
	| { state: 'unavailable'; detail: string }
	| { state: 'unreachable' };

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	const session = requireSession(locals, url);
	let apiStatus: ApiStatus;
	try {
		// Must exceed the API's own DB connect timeout (3 s, ~4 s measured), or a database outage
		// is misreported as the API being unreachable.
		const res = await fetch(`${VULNEX_API_URL}/readyz`, { signal: AbortSignal.timeout(8000) });
		const body = await res.json();
		apiStatus = res.ok
			? { state: 'ready', version: String(body.version) }
			: { state: 'unavailable', detail: String(body.detail ?? res.statusText) };
	} catch {
		apiStatus = { state: 'unreachable' };
	}
	// Each panel loads independently: a failure or a missing permission hides only that panel.
	const get = async <T>(path: string, permission: Parameters<typeof can>[1]) => {
		if (!can(session, permission) || apiStatus.state !== 'ready') return null;
		try {
			return await api<T>(fetch, path, { token: locals.token });
		} catch (e) {
			if (e instanceof ApiError) return null;
			throw e;
		}
	};
	const [summary, assets, scans, intel] = await Promise.all([
		get<FindingSummary>('/api/v1/findings/summary', 'findings.read'),
		get<AssetPage>('/api/v1/assets?limit=1', 'assets.read'),
		get<ScanPage>('/api/v1/scans?limit=5', 'scans.read'),
		get<{ sources: IntelSource[] }>('/api/v1/intel/sources', 'intel.read')
	]);
	return {
		api: apiStatus,
		checkedAt: new Date().toISOString(),
		summary,
		assetTotal: assets?.total ?? null,
		scans,
		intel: intel?.sources ?? null
	};
};
