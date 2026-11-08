import type { Handle } from '@sveltejs/kit/hooks';
import { ApiError, api } from '#lib/server/api.js';
import { SESSION_COOKIE, clearSessionCookie } from '#lib/server/session.js';
import type { Session } from '#lib/types.js';

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.token = null;
	event.locals.session = null;
	event.locals.sessionError = null;

	const token = event.cookies.get(SESSION_COOKIE);
	if (token) {
		try {
			event.locals.session = await api<Session>(event.fetch, '/api/v1/auth/session', { token });
			event.locals.token = token;
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) clearSessionCookie(event.cookies);
			else event.locals.sessionError = e instanceof ApiError ? e.detail : 'Session check failed';
		}
	}

	const response = await resolve(event);
	response.headers.set('x-frame-options', 'DENY');
	response.headers.set('x-content-type-options', 'nosniff');
	response.headers.set('referrer-policy', 'same-origin');
	// Signed-in pages hold tenant data: never let a shared cache keep them.
	if (event.locals.session) response.headers.set('cache-control', 'no-store');
	return response;
};
