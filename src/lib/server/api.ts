// Typed, server-only client for the VULNEX API. The browser never calls the API directly:
// the console holds the session token in an HttpOnly cookie and calls the API on its behalf.
import { VULNEX_API_URL } from '$app/env/private';

export class ApiError extends Error {
	constructor(
		readonly status: number,
		readonly detail: string,
		readonly errors: { loc: (string | number)[]; msg: string }[] = []
	) {
		super(detail);
	}
}

interface Options {
	token?: string | null;
	method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
	body?: unknown;
	/** The browser's address, forwarded so the API can throttle per client. */
	clientAddress?: string;
}

export async function api<T>(
	fetch: typeof globalThis.fetch,
	path: string,
	{ token, method = 'GET', body, clientAddress }: Options = {}
): Promise<T> {
	const headers: Record<string, string> = { accept: 'application/json' };
	if (body !== undefined) headers['content-type'] = 'application/json';
	if (token) headers.authorization = `Bearer ${token}`;
	if (clientAddress) headers['x-forwarded-for'] = clientAddress;

	let res: Response;
	try {
		res = await fetch(`${VULNEX_API_URL}${path}`, {
			method,
			headers,
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(10_000)
		});
	} catch {
		throw new ApiError(503, 'The VULNEX API is unreachable. Try again shortly.');
	}
	if (res.status === 204) return undefined as T;

	let data: unknown = null;
	try {
		data = await res.json();
	} catch {
		// Non-JSON body (proxy error page and similar): fall through to a generic message.
	}
	if (!res.ok) {
		const problem = (data ?? {}) as { detail?: string; title?: string; errors?: [] };
		throw new ApiError(
			res.status,
			problem.detail ?? problem.title ?? `Request failed (${res.status})`,
			problem.errors
		);
	}
	return data as T;
}

/** First validation message for a field, from a 422 problem response. */
export const fieldError = (e: ApiError, field: string) =>
	e.errors.find((x) => x.loc.at(-1) === field)?.msg;
