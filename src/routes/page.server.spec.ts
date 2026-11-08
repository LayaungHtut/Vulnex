import { describe, expect, it } from 'vitest';
import { load } from './+page.server';

type LoadEvent = Parameters<typeof load>[0];

const run = async (fetch: typeof globalThis.fetch) => {
	const result = await load({ fetch } as LoadEvent);
	if (!result) throw new Error('load returned nothing');
	return result.api;
};

const json = (status: number, body: unknown) => async () =>
	new Response(JSON.stringify(body), { status });

describe('status page load', () => {
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
});
