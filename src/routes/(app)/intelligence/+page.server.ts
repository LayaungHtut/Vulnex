import { ApiError, api } from '#lib/server/api.js';
import { requireSession } from '#lib/server/session.js';
import type { CveIntel, IntelSource } from '#lib/types.js';
import type { PageServerLoad } from './$types';

type Cve = CveIntel & {
	matches?: {
		vendor: string;
		product: string;
		version: string | null;
		start_including: string | null;
		start_excluding: string | null;
		end_including: string | null;
		end_excluding: string | null;
		conditional: boolean;
	}[];
};

export const load: PageServerLoad = async ({ fetch, locals, url }) => {
	requireSession(locals, url, 'intel.read');
	const opts = { token: locals.token };
	const cveId = url.searchParams.get('cve')?.trim().toUpperCase() ?? '';
	const q = url.searchParams.get('q')?.trim() ?? '';
	const kev = url.searchParams.get('kev') === 'true';
	try {
		const { sources, notice } = await api<{ sources: IntelSource[]; notice: string }>(
			fetch,
			'/api/v1/intel/sources',
			opts
		);
		let cve: Cve | null = null;
		let cveMissing = false;
		if (/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
			try {
				cve = await api<Cve>(fetch, `/api/v1/intel/cves/${cveId}`, opts);
			} catch (e) {
				if (!(e instanceof ApiError) || e.status !== 404) throw e;
				cveMissing = true;
			}
		}
		const search = new URLSearchParams({ limit: '50' });
		if (q) search.set('q', q);
		if (kev) search.set('kev', 'true');
		const results = await api<{ items: CveIntel[]; total: number }>(
			fetch,
			`/api/v1/intel/cves?${search}`,
			opts
		);
		return { sources, notice, cve, cveId, cveMissing, results, loadError: null };
	} catch (e) {
		if (!(e instanceof ApiError)) throw e;
		return {
			sources: [] as IntelSource[],
			notice: '',
			cve: null,
			cveId,
			cveMissing: false,
			results: { items: [] as CveIntel[], total: 0 },
			loadError: e.detail
		};
	}
};
