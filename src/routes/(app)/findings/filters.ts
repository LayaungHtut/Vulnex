import { error } from '@sveltejs/kit';
import { requireSession } from '#lib/server/session.js';
import { can } from '#lib/types.js';

// Query parameters the console forwards to GET /api/v1/findings; anything else is dropped.
const MULTI = ['status', 'severity', 'confidence', 'band'] as const;
const SINGLE = ['asset_id', 'assignee', 'kev', 'q', 'sort', 'offset'] as const;

export function findingQuery(url: URL, defaults: Record<string, string> = { status: 'active' }) {
	const out = new URLSearchParams();
	const has = (k: string) => url.searchParams.has(k);
	for (const k of MULTI) {
		const values = has(k) ? url.searchParams.getAll(k) : defaults[k] ? [defaults[k]] : [];
		for (const v of values) if (v) out.append(k, v);
	}
	for (const k of SINGLE) {
		const v = url.searchParams.get(k) ?? defaults[k];
		if (v) out.set(k, v);
	}
	return out;
}

/** Findings are visible with findings.read, or (assigned ones only) with findings.work. */
export function requireFindings(locals: App.Locals, url: URL) {
	const session = requireSession(locals, url);
	if (!can(session, 'findings.read') && !can(session, 'findings.work')) {
		error(403, 'Your role does not allow this.');
	}
	return session;
}
