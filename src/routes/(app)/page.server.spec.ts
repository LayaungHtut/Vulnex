import { describe, expect, it } from 'vitest';
import type { Session } from '#lib/types.js';
import { load } from './+page.server';

type LoadEvent = Parameters<typeof load>[0];

const session = {
	user: { id: 'u', email: 'a@example.test', display_name: 'A' },
	organization: { id: 'o', name: 'Org' },
	role: 'viewer',
	permissions: ['organization.read'],
	expires_at: '2026-11-08T12:00:00Z',
	memberships: []
} satisfies Session;

const run = async (fetch: typeof globalThis.fetch) => {
	const result = await load({
		fetch,
		locals: { session, token: 't', sessionError: null },
		url: new URL('http://console.test/')
	} as unknown as LoadEvent);
	if (!result) throw new Error('load returned nothing');
	return result.api;
};

const json = (status: number, body: unknown) => async () =>
	new Response(JSON.stringify(body), { status });

describe('overview load: system status', () => {
	it('reports ready with the API version', async () => {
		expect(await run(json(200, { status: 'ready', version: '0.1.0' }))).toEqual({
			state: 'ready',
			version: '0.1.0'
		});
	});

	it('reports the problem detail when the API is not ready', async () => {
		expect(await run(json(503, { status: 503, detail: 'Database unavailable' }))).toEqual({
			state: 'unavailable',
			detail: 'Database unavailable'
		});
	});

	it('reports unreachable when the request fails', async () => {
		const refused = async () => {
			throw new TypeError('fetch failed');
		};
		expect(await run(refused)).toEqual({ state: 'unreachable' });
	});

	it('redirects to sign-in without a session', async () => {
		await expect(
			load({
				fetch: json(200, {}),
				locals: { session: null, token: null, sessionError: null },
				url: new URL('http://console.test/')
			} as unknown as LoadEvent)
		).rejects.toMatchObject({ status: 303, location: '/login?next=%2F' });
	});
});
