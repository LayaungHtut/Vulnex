import { describe, expect, it } from 'vitest';
import type { Session } from '#lib/types.js';
import { ApiError, api, fieldError } from './api';
import { requireSession, safeNext } from './session';

describe('safeNext (open-redirect guard)', () => {
	it.each([
		['/members', '/members'],
		['/audit?before=10', '/audit?before=10'],
		[null, '/'],
		['', '/'],
		['https://evil.test/', '/'],
		['//evil.test/x', '/'],
		['/\\evil.test', '/'],
		['javascript:alert(1)', '/']
	])('%s -> %s', (input, expected) => {
		expect(safeNext(input)).toBe(expected);
	});
});

describe('requireSession', () => {
	const url = new URL('http://console.test/members?x=1');
	const session = { permissions: ['organization.read'] } as unknown as Session;

	it('redirects anonymous users to sign-in, keeping the destination', () => {
		expect(() => requireSession({ session: null, token: null, sessionError: null }, url)).toThrow(
			expect.objectContaining({ status: 303, location: '/login?next=%2Fmembers%3Fx%3D1' })
		);
	});

	it('reports an API outage instead of pretending the user is signed out', () => {
		expect(() =>
			requireSession({ session: null, token: null, sessionError: 'API down' }, url)
		).toThrow(expect.objectContaining({ status: 503 }));
	});

	it('refuses a missing permission with 403', () => {
		expect(() =>
			requireSession({ session, token: 't', sessionError: null }, url, 'members.manage')
		).toThrow(expect.objectContaining({ status: 403 }));
		expect(requireSession({ session, token: 't', sessionError: null }, url)).toBe(session);
	});
});

describe('api client', () => {
	const respond = (status: number, body?: unknown) => async () =>
		new Response(body === undefined ? null : JSON.stringify(body), { status });

	it('sends the bearer token and forwarded address, and parses JSON', async () => {
		let seen: RequestInit | undefined;
		const fetch = async (_: RequestInfo | URL, init?: RequestInit) => {
			seen = init;
			return new Response('{"ok":true}', { status: 200 });
		};
		expect(
			await api(fetch as typeof globalThis.fetch, '/x', {
				token: 'tok',
				method: 'POST',
				body: { a: 1 },
				clientAddress: '198.51.100.7'
			})
		).toEqual({ ok: true });
		const headers = seen?.headers as Record<string, string>;
		expect(headers.authorization).toBe('Bearer tok');
		expect(headers['x-forwarded-for']).toBe('198.51.100.7');
		expect(seen?.body).toBe('{"a":1}');
	});

	it('turns problem+json into ApiError with the detail and field errors', async () => {
		const err = await api(
			respond(422, {
				status: 422,
				detail: 'Request validation failed',
				errors: [{ loc: ['body', 'password'], msg: 'too short' }]
			}),
			'/x'
		).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ApiError);
		expect((err as ApiError).status).toBe(422);
		expect(fieldError(err as ApiError, 'password')).toBe('too short');
	});

	it('maps network failure to 503 and handles 204', async () => {
		const refused = async () => {
			throw new TypeError('fetch failed');
		};
		await expect(api(refused, '/x')).rejects.toMatchObject({ status: 503 });
		expect(await api(respond(204), '/x')).toBeUndefined();
	});
});
