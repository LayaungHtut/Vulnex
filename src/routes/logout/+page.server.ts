import { redirect } from '@sveltejs/kit';
import { api } from '#lib/server/api.js';
import { clearSessionCookie } from '#lib/server/session.js';
import type { Actions, PageServerLoad } from './$types';

// Sign-out is a POST (form action) so a link or image elsewhere cannot sign someone out.
export const load: PageServerLoad = () => redirect(303, '/');

export const actions: Actions = {
	default: async ({ locals, cookies, fetch, getClientAddress }) => {
		if (locals.token) {
			try {
				await api(fetch, '/api/v1/auth/logout', {
					method: 'POST',
					token: locals.token,
					clientAddress: getClientAddress()
				});
			} catch {
				// Still clear the cookie; the server-side session then expires on its own.
			}
		}
		clearSessionCookie(cookies);
		redirect(303, '/login');
	}
};
