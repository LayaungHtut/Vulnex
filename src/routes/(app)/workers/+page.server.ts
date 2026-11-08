import { fail } from '@sveltejs/kit';
import { ApiError, api } from '#lib/server/api.js';
import { field, mutate } from '#lib/server/actions.js';
import { requireSession } from '#lib/server/session.js';
import {
	can,
	type Enrollment,
	type EnrollmentCreated,
	type ScopeGroup,
	type Worker
} from '#lib/types.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	const session = requireSession(locals, url, 'workers.read');
	const token = locals.token;
	const manage = can(session, 'workers.manage');
	try {
		const [workers, enrollments, groups] = await Promise.all([
			api<Worker[]>(fetch, '/api/v1/workers', { token }),
			manage ? api<Enrollment[]>(fetch, '/api/v1/workers/enrollments', { token }) : [],
			manage ? api<ScopeGroup[]>(fetch, '/api/v1/scope-groups', { token }) : []
		]);
		return { workers, enrollments, groups, loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return {
			workers: [] as Worker[],
			enrollments: [] as Enrollment[],
			groups: [] as ScopeGroup[],
			loadError: e.detail
		};
	}
};

export const actions: Actions = {
	/** The bundle (with its single-use token) is returned once, to this response only. */
	enroll: async (event) => {
		requireSession(event.locals, event.url, 'workers.manage');
		const form = await event.request.formData();
		const values = { name: field(form, 'name'), scope_group_id: field(form, 'scope_group_id') };
		try {
			const created = await api<EnrollmentCreated>(event.fetch, '/api/v1/workers/enrollments', {
				method: 'POST',
				body: { ...values, ttl_hours: Number(field(form, 'ttl_hours')) || 24 },
				token: event.locals.token,
				clientAddress: event.getClientAddress()
			});
			return {
				action: 'enroll',
				name: values.name,
				expires_at: created.expires_at,
				bundle: JSON.stringify(created.bundle, null, 2)
			};
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
			const message = e.status === 422 ? 'Check the form and try again.' : e.detail;
			return fail(e.status, { action: 'enroll', message, values });
		}
	},

	revokeEnrollment: async (event) => {
		const id = field(await event.request.formData(), 'id');
		return mutate(
			event,
			'revokeEnrollment',
			'workers.manage',
			{ path: `/api/v1/workers/enrollments/${encodeURIComponent(id)}`, method: 'DELETE' },
			'Enrollment token withdrawn.'
		);
	},

	revoke: async (event) => {
		const id = field(await event.request.formData(), 'id');
		return mutate(
			event,
			'revoke',
			'workers.manage',
			{ path: `/api/v1/workers/${encodeURIComponent(id)}/revoke`, method: 'POST' },
			'Scanner revoked. Its certificate no longer works and its running tasks were released.'
		);
	}
};
