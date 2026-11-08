import { ApiError, api } from '#lib/server/api.js';
import { field, loadOne, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import {
	CRITICALITIES,
	can,
	type Asset,
	type AuditPage,
	type FindingPage,
	type Scan,
	type ServicePage
} from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

const base = (id: string) => `/api/v1/assets/${encodeURIComponent(id)}`;

export const load: PageServerLoad = async (event) => {
	const session = requireSession(event.locals, event.url, 'assets.read');
	const asset = await loadOne<Asset>(event, base(event.params.id));
	let history: AuditPage | null = null;
	let historyError: string | null = null;
	if (can(session, 'audit.read')) {
		try {
			history = await api<AuditPage>(
				event.fetch,
				`/api/v1/audit-events?target_type=asset&target_id=${asset.id}&limit=20`,
				{ token: event.locals.token }
			);
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			historyError = e.detail;
		}
	}
	const opts = { token: event.locals.token };
	const id = encodeURIComponent(asset.id);
	const [services, findings] = await Promise.all([
		api<ServicePage>(event.fetch, `/api/v1/services?asset_id=${id}&limit=200`, opts).catch(
			() => null
		),
		can(session, 'findings.read')
			? api<FindingPage>(
					event.fetch,
					`/api/v1/findings?asset_id=${id}&status=active&limit=50`,
					opts
				).catch(() => null)
			: null
	]);
	return { asset, history, historyError, services, findings };
};

export const actions: Actions = {
	update: async (event) => {
		const form = await event.request.formData();
		const criticality = CRITICALITIES.find((c) => c === field(form, 'criticality'));
		return mutate(
			event,
			'update',
			'assets.manage',
			{
				path: base(event.params.id),
				method: 'PATCH',
				body: { name: field(form, 'name'), notes: field(form, 'notes'), criticality }
			},
			'Saved.'
		);
	},

	retire: (event) =>
		mutate(
			event,
			'retire',
			'assets.manage',
			{ path: `${base(event.params.id)}/retire`, method: 'POST' },
			'Asset retired. It will not be scanned; its history is kept.'
		),

	reactivate: (event) =>
		mutate(
			event,
			'reactivate',
			'assets.manage',
			{ path: `${base(event.params.id)}/reactivate`, method: 'POST' },
			'Asset reactivated.'
		),

	scan: async (event) => {
		const form = await event.request.formData();
		const profile = field(form, 'profile') === 'scope_check' ? 'scope_check' : 'discovery';
		const result = await mutate<Scan>(
			event,
			'scan',
			'scans.run',
			{ path: '/api/v1/scans', method: 'POST', body: { asset_ids: [event.params.id], profile } },
			(s) => s.id
		);
		if ('success' in result) redirect(303, resolve('/(app)/scans/[id]', { id: result.success }));
		return result;
	}
};
