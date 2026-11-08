import { fail, redirect } from '@sveltejs/kit';
import { ApiError, api } from '#lib/server/api.js';
import { safeNext, setSessionCookie } from '#lib/server/session.js';
import type { LoginResponse } from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = ({ locals, url }) => {
	if (locals.session) redirect(303, safeNext(url.searchParams.get('next')));
	return { apiError: locals.sessionError };
};

export const actions: Actions = {
	default: async ({ request, cookies, fetch, url, getClientAddress }) => {
		const form = await request.formData();
		const email = String(form.get('email') ?? '').trim();
		const password = String(form.get('password') ?? '');
		if (!email || !password) {
			return fail(400, { email, message: 'Enter your email address and password.' });
		}

		let result: LoginResponse;
		try {
			result = await api<LoginResponse>(fetch, '/api/v1/auth/login', {
				method: 'POST',
				body: { email, password },
				clientAddress: getClientAddress()
			});
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			const message =
				e.status === 401 || e.status === 422 ? 'Invalid email or password.' : e.detail;
			return fail(e.status === 429 ? 429 : 400, { email, message });
		}

		setSessionCookie(cookies, result.token, result.session.expires_at, url);
		redirect(303, safeNext(url.searchParams.get('next')));
	}
};
