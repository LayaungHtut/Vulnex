import { requireSession } from '#lib/server/session.js';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ locals, url }) => ({
	session: requireSession(locals, url)
});
