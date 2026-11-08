import { ApiError, api } from '#lib/server/api.js';
import { field, loadOne, mutate } from '#lib/server/actions.js';
import { can, type FindingDetail, type Member } from '#lib/types.js';
import { requireFindings } from '../filters.js';
import type { Actions, PageServerLoad } from './$types';

const base = (id: string) => `/api/v1/findings/${encodeURIComponent(id)}`;

export const load: PageServerLoad = async (event) => {
	const session = requireFindings(event.locals, event.url);
	const finding = await loadOne<FindingDetail>(event, base(event.params.id));
	let members: Member[] = [];
	if (can(session, 'findings.triage') && can(session, 'members.read')) {
		try {
			members = await api<Member[]>(event.fetch, '/api/v1/members', { token: event.locals.token });
		} catch (e) {
			if (!(e instanceof ApiError)) throw e;
		}
	}
	return { finding, members };
};

export const actions: Actions = {
	status: async (event) => {
		const form = await event.request.formData();
		const body: Record<string, string | null> = {
			status: field(form, 'status'),
			reason: field(form, 'reason') || null
		};
		if (field(form, 'accepted_until')) body.accepted_until = field(form, 'accepted_until');
		return mutate(
			event,
			'status',
			'findings.work',
			{ path: base(event.params.id), method: 'PATCH', body },
			'Status updated.',
			{ reason: field(form, 'reason') }
		);
	},

	assign: async (event) => {
		const form = await event.request.formData();
		const assignee = field(form, 'assignee_id');
		return mutate(
			event,
			'assign',
			'findings.triage',
			{
				path: base(event.params.id),
				method: 'PATCH',
				body: {
					...(assignee ? { assignee_id: assignee } : { unassign: true }),
					due_date: field(form, 'due_date') || null
				}
			},
			'Assignment saved.'
		);
	},

	comment: async (event) => {
		const form = await event.request.formData();
		return mutate(
			event,
			'comment',
			'findings.work',
			{
				path: `${base(event.params.id)}/comments`,
				method: 'POST',
				body: { text: field(form, 'text') }
			},
			'Comment added.',
			{ text: field(form, 'text') }
		);
	}
};
