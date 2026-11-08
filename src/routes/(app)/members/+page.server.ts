import { fail } from '@sveltejs/kit';
import { ApiError, api, fieldError } from '#lib/server/api.js';
import { requireSession } from '#lib/server/session.js';
import { ROLES, type Member, type Role } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url, 'members.read');
	try {
		return {
			members: await api<Member[]>(fetch, '/api/v1/members', { token: locals.token }),
			loadError: null
		};
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return { members: [] as Member[], loadError: e.detail };
	}
};

const role = (value: FormDataEntryValue | null): Role | null =>
	ROLES.includes(value as Role) ? (value as Role) : null;

// The permission checks here only shape the UI; the API makes the authorization decision
// (including owner rules) and its answer is shown to the user.
export const actions: Actions = {
	add: async ({ request, fetch, locals, url, getClientAddress }) => {
		requireSession(locals, url, 'members.manage');
		const form = await request.formData();
		const values = {
			email: String(form.get('email') ?? '').trim(),
			display_name: String(form.get('display_name') ?? '').trim(),
			role: role(form.get('role')),
			password: String(form.get('password') ?? '')
		};
		if (!values.email || !values.display_name || !values.role || !values.password) {
			return fail(400, { action: 'add', values, message: 'All fields are required.' });
		}
		try {
			const member = await api<Member>(fetch, '/api/v1/members', {
				method: 'POST',
				token: locals.token,
				clientAddress: getClientAddress(),
				body: values
			});
			return { action: 'add', success: `${member.email} was added.` };
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			const message =
				e.status === 422
					? (fieldError(e, 'password') && 'The password must be 12 to 128 characters.') ||
						(fieldError(e, 'email') && 'Enter a valid email address.') ||
						'Check the form and try again.'
					: e.detail;
			return fail(e.status, { action: 'add', values: { ...values, password: '' }, message });
		}
	},

	role: async ({ request, fetch, locals, url, getClientAddress }) => {
		requireSession(locals, url, 'members.manage');
		const form = await request.formData();
		const userId = String(form.get('user_id') ?? '');
		const newRole = role(form.get('role'));
		if (!newRole) return fail(400, { action: 'role', userId, message: 'Choose a role.' });
		try {
			await api(fetch, `/api/v1/members/${encodeURIComponent(userId)}`, {
				method: 'PATCH',
				token: locals.token,
				clientAddress: getClientAddress(),
				body: { role: newRole }
			});
			return { action: 'role', userId, success: 'Role updated.' };
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			return fail(e.status, { action: 'role', userId, message: e.detail });
		}
	},

	remove: async ({ request, fetch, locals, url, getClientAddress }) => {
		requireSession(locals, url, 'members.manage');
		const userId = String((await request.formData()).get('user_id') ?? '');
		try {
			await api(fetch, `/api/v1/members/${encodeURIComponent(userId)}`, {
				method: 'DELETE',
				token: locals.token,
				clientAddress: getClientAddress()
			});
			return { action: 'remove', userId, success: 'Member removed.' };
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			return fail(e.status, { action: 'remove', userId, message: e.detail });
		}
	}
};
