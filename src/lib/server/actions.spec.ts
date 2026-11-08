import type { RequestEvent } from '@sveltejs/kit';
import { describe, expect, it, vi } from 'vitest';
import type { Permission, Session } from '#lib/types.js';
import { loadOne, mutate } from './actions';

vi.mock('$app/env/private', () => ({ VULNEX_API_URL: 'http://api.test' }));

const session = { permissions: ['assets.manage'] as Permission[] } as Session;

function event(status: number, body: unknown) {
	const calls: { url: string; init: RequestInit }[] = [];
	const fetch = async (url: string, init: RequestInit) => {
		calls.push({ url, init });
		return new Response(status === 204 ? null : JSON.stringify(body), { status });
	};
	const ev = {
		fetch,
		locals: { session, token: 'tok', sessionError: null },
		url: new URL('http://console.test/assets'),
		getClientAddress: () => '198.51.100.7'
	} as unknown as RequestEvent;
	return { ev, calls };
}

describe('mutate', () => {
	it('sends the token and client address, and reports success', async () => {
		const { ev, calls } = event(201, { target: '10.0.0.1' });
		const result = await mutate<{ target: string }>(
			ev,
			'add',
			'assets.manage',
			{ path: '/api/v1/assets', method: 'POST', body: { target: '10.0.0.1' } },
			(a) => `${a.target} was added.`
		);
		expect(result).toEqual({ action: 'add', success: '10.0.0.1 was added.' });
		const headers = calls[0].init.headers as Record<string, string>;
		expect(headers.authorization).toBe('Bearer tok');
		expect(headers['x-forwarded-for']).toBe('198.51.100.7');
	});

	it("shows the API's refusal and keeps the typed values", async () => {
		const { ev } = event(422, { detail: '10.9.9.9 is not inside any included range' });
		const result = await mutate(
			ev,
			'add',
			'assets.manage',
			{ path: '/api/v1/assets', method: 'POST' },
			'ok',
			{ target: '10.9.9.9' }
		);
		expect(result).toMatchObject({
			status: 422,
			data: {
				action: 'add',
				message: '10.9.9.9 is not inside any included range',
				values: { target: '10.9.9.9' }
			}
		});
	});

	it('does not call the API without the permission', async () => {
		const { ev, calls } = event(200, {});
		await expect(
			mutate(ev, 'x', 'scope.manage', { path: '/api/v1/scope-groups', method: 'POST' }, 'ok')
		).rejects.toMatchObject({ status: 403 });
		expect(calls).toHaveLength(0);
	});
});

describe('loadOne', () => {
	it.each([404, 422])('maps API %i (other tenant or malformed ID) to a plain 404', async (s) => {
		const { ev } = event(s, { detail: 'Asset not found' });
		await expect(loadOne(ev, '/api/v1/assets/x')).rejects.toMatchObject({ status: 404 });
	});

	it('reports an API outage as 503', async () => {
		const { ev } = event(500, { detail: 'boom' });
		await expect(loadOne(ev, '/api/v1/assets/x')).rejects.toMatchObject({ status: 503 });
	});
});
