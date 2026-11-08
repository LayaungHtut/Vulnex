import { ApiError, api } from '#lib/server/api.js';
import { field, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import { CRITICALITIES, can, type Asset, type AssetPage, type ScopeGroup } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

const PAGE_SIZE = 50;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Filters from the URL, normalised to values the API accepts (anything else is dropped). */
function filters(url: URL) {
	const p = url.searchParams;
	const status = ['active', 'retired', 'all'].find((s) => s === p.get('status')) ?? 'active';
	const group = UUID.test(p.get('scope_group_id') ?? '') ? p.get('scope_group_id')! : '';
	const criticality = CRITICALITIES.find((c) => c === p.get('criticality')) ?? '';
	const q = (p.get('q') ?? '').trim().slice(0, 100);
	const page = Math.max(1, Math.min(2000, Number.parseInt(p.get('page') ?? '1', 10) || 1));
	return { status, scope_group_id: group, criticality, q, page };
}

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	const session = requireSession(locals, url, 'assets.read');
	const f = filters(url);
	const query = new URLSearchParams({
		status: f.status,
		limit: String(PAGE_SIZE),
		offset: String((f.page - 1) * PAGE_SIZE)
	});
	if (f.scope_group_id) query.set('scope_group_id', f.scope_group_id);
	if (f.criticality) query.set('criticality', f.criticality);
	if (f.q) query.set('q', f.q);
	try {
		const [assets, groups] = await Promise.all([
			api<AssetPage>(fetch, `/api/v1/assets?${query}`, { token: locals.token }),
			// Viewers may see assets but not scope definitions; they get no group filter.
			can(session, 'scope.read')
				? api<ScopeGroup[]>(fetch, '/api/v1/scope-groups', { token: locals.token })
				: Promise.resolve([] as ScopeGroup[])
		]);
		return { assets, groups, filters: f, pageSize: PAGE_SIZE, loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return {
			assets: { items: [], total: 0 } as AssetPage,
			groups: [] as ScopeGroup[],
			filters: f,
			pageSize: PAGE_SIZE,
			loadError: e.detail
		};
	}
};

export const actions: Actions = {
	add: async (event) => {
		const form = await event.request.formData();
		const values = {
			scope_group_id: field(form, 'scope_group_id'),
			target: field(form, 'target'),
			name: field(form, 'name'),
			criticality: CRITICALITIES.find((c) => c === field(form, 'criticality')) ?? 'medium'
		};
		return mutate<Asset>(
			event,
			'add',
			'assets.manage',
			{ path: '/api/v1/assets', method: 'POST', body: values },
			(a) => `${a.target} was added.`,
			values
		);
	}
};
