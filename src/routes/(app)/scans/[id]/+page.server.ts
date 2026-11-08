import { api } from '#lib/server/api.js';
import { loadOne, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import type { Evidence, Scan } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

const base = (id: string) => `/api/v1/scans/${encodeURIComponent(id)}`;

export const load: PageServerLoad = async (event) => {
	requireSession(event.locals, event.url, 'scans.read');
	const scan = await loadOne<Scan>(event, base(event.params.id));
	const evidence =
		scan.profile === 'discovery' && scan.summary
			? await api<Evidence[]>(event.fetch, `${base(scan.id)}/evidence`, {
					token: event.locals.token
				}).catch(() => null)
			: null;
	return { scan, evidence };
};

export const actions: Actions = {
	cancel: (event) =>
		mutate(
			event,
			'cancel',
			'scans.run',
			{ path: `${base(event.params.id)}/cancel`, method: 'POST' },
			'Cancellation requested.'
		)
};
