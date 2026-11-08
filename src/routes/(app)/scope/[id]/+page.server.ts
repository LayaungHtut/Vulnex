import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import { field, loadOne, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import type { ScopeGroup } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

const base = (id: string) => `/api/v1/scope-groups/${encodeURIComponent(id)}`;

export const load: PageServerLoad = async (event) => {
	requireSession(event.locals, event.url, 'scope.read');
	return { group: await loadOne<ScopeGroup>(event, base(event.params.id)) };
};

export const actions: Actions = {
	addEntry: async (event) => {
		const form = await event.request.formData();
		const value = field(form, 'value');
		return mutate(
			event,
			'addEntry',
			'scope.manage',
			{
				path: `${base(event.params.id)}/entries`,
				method: 'POST',
				body: { value, exclude: form.get('exclude') === 'on', note: field(form, 'note') }
			},
			`${value} was added.`
		);
	},

	removeEntry: async (event) => {
		const id = field(await event.request.formData(), 'entry_id');
		return mutate(
			event,
			'removeEntry',
			'scope.manage',
			{ path: `${base(event.params.id)}/entries/${encodeURIComponent(id)}`, method: 'DELETE' },
			'Entry removed.'
		);
	},

	authorize: async (event) => {
		const form = await event.request.formData();
		if (form.get('confirm') !== 'on') {
			return { action: 'authorize', message: 'Confirm the statement to authorize this scope.' };
		}
		return mutate(
			event,
			'authorize',
			'scope.manage',
			{ path: `${base(event.params.id)}/authorization`, method: 'POST', body: { confirm: true } },
			'Scope authorized.'
		);
	},

	revoke: (event) =>
		mutate(
			event,
			'revoke',
			'scope.manage',
			{ path: `${base(event.params.id)}/authorization`, method: 'DELETE' },
			'Authorization withdrawn.'
		),

	update: async (event) => {
		const form = await event.request.formData();
		return mutate(
			event,
			'update',
			'scope.manage',
			{
				path: base(event.params.id),
				method: 'PATCH',
				body: { name: field(form, 'name'), description: field(form, 'description') }
			},
			'Saved.'
		);
	},

	delete: async (event) => {
		const result = await mutate(
			event,
			'delete',
			'scope.manage',
			{ path: base(event.params.id), method: 'DELETE' },
			'Deleted.'
		);
		if ('success' in result) redirect(303, resolve('/(app)/scope'));
		return result;
	}
};
