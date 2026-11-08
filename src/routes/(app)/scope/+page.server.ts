import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import { ApiError, api } from '#lib/server/api.js';
import { field, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import type { ScopeGroup } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url, 'scope.read');
	try {
		const groups = await api<ScopeGroup[]>(fetch, '/api/v1/scope-groups', { token: locals.token });
		return { groups, loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return { groups: [] as ScopeGroup[], loadError: e.detail };
	}
};

export const actions: Actions = {
	create: async (event) => {
		const form = await event.request.formData();
		const result = await mutate<ScopeGroup>(
			event,
			'create',
			'scope.manage',
			{
				path: '/api/v1/scope-groups',
				method: 'POST',
				body: { name: field(form, 'name'), description: field(form, 'description') }
			},
			(g) => g.id
		);
		if ('success' in result) redirect(303, resolve('/(app)/scope/[id]', { id: result.success }));
		return result;
	}
};
