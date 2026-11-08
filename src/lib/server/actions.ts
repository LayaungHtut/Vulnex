import { error, fail, type RequestEvent } from '@sveltejs/kit';
import { ApiError, api } from './api.js';
import { requireSession } from './session.js';
import type { Permission } from '#lib/types.js';

/** Text field from a form, trimmed. */
export const field = (form: FormData, name: string) => String(form.get(name) ?? '').trim();

/**
 * Run one API mutation for a form action. The permission check only shapes the UI flow; the API
 * makes the authorization decision, and its error message is shown to the user as is.
 */
export async function mutate<T>(
	event: RequestEvent,
	action: string,
	permission: Permission,
	request: { path: string; method: 'POST' | 'PATCH' | 'DELETE'; body?: unknown },
	success: string | ((result: T) => string),
	/** Echoed back on failure so the form keeps what the user typed. */
	values?: Record<string, string>
) {
	requireSession(event.locals, event.url, permission);
	try {
		const result = await api<T>(event.fetch, request.path, {
			...request,
			token: event.locals.token,
			clientAddress: event.getClientAddress()
		});
		return { action, success: typeof success === 'string' ? success : success(result) };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		const message =
			e.status === 422 && e.errors.length ? 'Check the form and try again.' : e.detail;
		return fail(e.status, { action, message, values });
	}
}

/** Load one object for a detail page: another tenant's or a malformed ID is a plain 404. */
export async function loadOne<T>(event: RequestEvent, path: string): Promise<T> {
	try {
		return await api<T>(event.fetch, path, { token: event.locals.token });
	} catch (e) {
		if (e instanceof ApiError && (e.status === 404 || e.status === 422)) error(404, 'Not found');
		if (e instanceof ApiError) error(e.status >= 500 ? 503 : e.status, e.detail);
		throw e;
	}
}
