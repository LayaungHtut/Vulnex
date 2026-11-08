import { loadOne, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import type { Scan } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

const base = (id: string) => `/api/v1/scans/${encodeURIComponent(id)}`;

export const load: PageServerLoad = async (event) => {
	requireSession(event.locals, event.url, 'scans.read');
	return { scan: await loadOne<Scan>(event, base(event.params.id)) };
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
