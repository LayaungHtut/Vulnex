import type { Cookies } from '@sveltejs/kit';
import { error, redirect } from '@sveltejs/kit';
import type { Permission, Session } from '#lib/types.js';

export const SESSION_COOKIE = 'vulnex_session';

export function setSessionCookie(cookies: Cookies, token: string, expiresAt: string, url: URL) {
	cookies.set(SESSION_COOKIE, token, {
		path: '/',
		httpOnly: true, // never readable by page scripts
		sameSite: 'lax', // plus SvelteKit's Origin check on every form post (CSRF)
		secure: url.protocol === 'https:',
		expires: new Date(expiresAt)
	});
}

export function clearSessionCookie(cookies: Cookies) {
	cookies.delete(SESSION_COOKIE, { path: '/' });
}

/**
 * Where to go after sign-in. Only same-site paths: rejects absolute URLs, scheme-relative
 * `//host` and backslash tricks, so `?next=` cannot become an open redirect.
 */
export function safeNext(next: string | null): string {
	if (!next || !next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '/';
	return next;
}

/**
 * The signed-in session, or a redirect to sign-in. Pages call this for clarity, but it is not
 * the security boundary: the API authorizes every request itself.
 */
export function requireSession(locals: App.Locals, url: URL, permission?: Permission): Session {
	if (!locals.session) {
		if (locals.sessionError) error(503, locals.sessionError);
		redirect(303, `/login?next=${encodeURIComponent(url.pathname + url.search)}`);
	}
	if (permission && !locals.session.permissions.includes(permission)) {
		error(403, 'Your role does not allow this.');
	}
	return locals.session;
}
