import { ApiError, api } from '#lib/server/api.js';
import { field, loadOne, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import { CRITICALITIES, can, type Asset, type AuditPage } from '#lib/types.js';
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
	return { asset, history, historyError };
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
		)
};
