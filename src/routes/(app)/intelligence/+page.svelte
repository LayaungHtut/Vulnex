<script lang="ts">
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import Notice from '#lib/components/Notice.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const when = (iso: string | null) =>
		iso
			? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
			: 'never';
	const pct = (v: number | null) => (v == null ? '—' : `${(v * 100).toFixed(2)}%`);
	const label = {
		nvd: 'NVD CVE records',
		kev: 'CISA Known Exploited Vulnerabilities',
		epss: 'FIRST EPSS scores'
	};
	type Match = NonNullable<NonNullable<typeof data.cve>['matches']>[number];
	const range = (m: Match) =>
		m.version
			? `= ${m.version}`
			: [
					m.start_including && `≥ ${m.start_including}`,
					m.start_excluding && `> ${m.start_excluding}`,
					m.end_including && `≤ ${m.end_including}`,
					m.end_excluding && `< ${m.end_excluding}`
				]
					.filter(Boolean)
					.join(', ') || 'all versions';
	const input =
		'block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>Vulnerability intelligence · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Vulnerability intelligence</h1>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	Reference data VULNEX correlates with what scans observe. NVD records are synced only for the
	products VULNEX can fingerprint. A failed sync keeps the last good data and is shown here, so
	stale data is never presented as current.
</p>

{#if data.loadError}
	<Notice message="Intelligence could not be loaded: {data.loadError}" />
{:else}
	<div class="mt-6 grid gap-4 md:grid-cols-3">
		{#each data.sources as s (s.name)}
			<section
				class="rounded-md border border-slate-200 bg-white p-4 text-sm"
				aria-label={label[s.name]}
			>
				<h2 class="font-medium">{label[s.name]}</h2>
				<p class="mt-1 flex items-center gap-2">
					<span
						aria-hidden="true"
						class={[
							'size-2 rounded-full',
							s.status === 'ok' && !s.stale
								? 'bg-emerald-600'
								: s.status === 'never'
									? 'bg-slate-400'
									: 'bg-amber-500'
						]}
					></span>
					{#if s.status === 'never'}
						Never synced
					{:else if s.stale}
						Stale (older than {s.max_age_hours} h)
					{:else if s.status === 'error'}
						Last attempt failed
					{:else}
						Current
					{/if}
				</p>
				<dl class="mt-3 space-y-1 text-xs text-slate-600">
					<div class="flex justify-between gap-2">
						<dt>Last success</dt>
						<dd>{when(s.last_success_at)}</dd>
					</div>
					<div class="flex justify-between gap-2">
						<dt>Records</dt>
						<dd class="tabular-nums">{s.records.toLocaleString()}</dd>
					</div>
					<div class="flex justify-between gap-2">
						<dt>Version</dt>
						<dd class="truncate">{s.source_version ?? '—'}</dd>
					</div>
				</dl>
				{#if s.error}
					<p class="mt-2 rounded bg-amber-50 px-2 py-1 text-xs break-words text-amber-900">
						{s.error}
					</p>
				{/if}
			</section>
		{/each}
	</div>
	{#if data.sources.some((s) => s.status === 'never')}
		<p class="mt-3 text-xs text-slate-500">
			Run <code class="font-mono">python -m vulnex.cli intel-sync</code> (or start Compose with
			<code class="font-mono">--profile intel</code>) to fetch the feeds.
		</p>
	{/if}

	<form method="GET" class="mt-8 flex flex-wrap items-end gap-3">
		<label class="text-xs text-slate-600">
			CVE ID
			<input name="cve" value={data.cveId} placeholder="CVE-2024-6387" class={input} />
		</label>
		<label class="min-w-64 flex-1 text-xs text-slate-600">
			Search descriptions
			<input name="q" value={page.url.searchParams.get('q') ?? ''} maxlength="100" class={input} />
		</label>
		<label class="flex items-center gap-1.5 pb-2 text-xs text-slate-600">
			<input
				type="checkbox"
				name="kev"
				value="true"
				checked={page.url.searchParams.get('kev') === 'true'}
			/>
			KEV only
		</label>
		<button class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white">Look up</button>
	</form>

	{#if data.cveMissing}
		<p class="mt-4 text-sm text-slate-600">
			{data.cveId} is not in the local store. Only CVEs affecting products VULNEX fingerprints are synced
			from NVD.
		</p>
	{:else if data.cve}
		{@const c = data.cve}
		<section
			class="mt-4 rounded-md border border-slate-200 bg-white p-4 text-sm"
			aria-labelledby="cve"
		>
			<h2 id="cve" class="font-mono font-semibold">{c.id}</h2>
			<p class="mt-2 leading-relaxed">{c.description}</p>
			<dl class="mt-4 grid gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
				<div>
					<dt class="text-slate-500">CVSS</dt>
					<dd>
						{c.cvss_score ?? '—'}
						{c.cvss_severity ?? ''}
						{c.cvss_version ? `(v${c.cvss_version}, ${c.cvss_source})` : ''}
					</dd>
				</div>
				<div>
					<dt class="text-slate-500">EPSS</dt>
					<dd>
						{pct(c.epss)} · percentile {pct(c.epss_percentile)}{c.epss_date
							? ` (${c.epss_date})`
							: ''}
					</dd>
				</div>
				<div>
					<dt class="text-slate-500">CISA KEV</dt>
					<dd>{c.kev ? `Listed ${c.kev_added}, due ${c.kev_due}` : 'Not listed'}</dd>
				</div>
				<div>
					<dt class="text-slate-500">CWE</dt>
					<dd>{c.cwes.join(', ') || '—'}</dd>
				</div>
				<div class="sm:col-span-4">
					<dt class="text-slate-500">Vector</dt>
					<dd class="font-mono">{c.cvss_vector ?? '—'}</dd>
				</div>
			</dl>
			{#if c.kev_action}<p class="mt-3 text-xs">
					<span class="font-medium">CISA required action:</span>
					{c.kev_action}
				</p>{/if}
			{#if c.matches?.length}
				<h3 class="mt-4 text-xs font-medium text-slate-500 uppercase">
					Affected (as published by NVD)
				</h3>
				<ul class="mt-1 space-y-0.5 font-mono text-xs">
					{#each c.matches as m, i (i)}
						<li>
							{m.vendor}:{m.product}
							{range(m)}{m.conditional
								? ' (only with certain platforms; not matched remotely)'
								: ''}
						</li>
					{/each}
				</ul>
			{/if}
			{#if c.refs.length}
				<h3 class="mt-4 text-xs font-medium text-slate-500 uppercase">References</h3>
				<ul class="mt-1 space-y-0.5 text-xs">
					{#each c.refs.slice(0, 15) as r (r.url)}
						<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external reference -->
						<li>
							<a
								href={r.url}
								rel="noopener noreferrer external"
								target="_blank"
								class="break-all underline">{r.url}</a
							>{r.tags.length ? ` · ${r.tags.join(', ')}` : ''}
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/if}

	<section class="mt-6" aria-labelledby="list">
		<h2 id="list" class="text-sm font-medium">
			{data.results.total.toLocaleString()} CVE record{data.results.total === 1 ? '' : 's'}
			<span class="font-normal text-slate-500">· newest first</span>
		</h2>
		{#if data.results.items.length}
			<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="w-full text-left text-sm">
					<thead class="border-b border-slate-200 text-xs text-slate-500">
						<tr>
							<th scope="col" class="px-3 py-2 font-medium">CVE</th>
							<th scope="col" class="px-3 py-2 font-medium">CVSS</th>
							<th scope="col" class="px-3 py-2 font-medium">EPSS</th>
							<th scope="col" class="px-3 py-2 font-medium">KEV</th>
							<th scope="col" class="px-3 py-2 font-medium">Description</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-slate-100 align-top">
						{#each data.results.items as c (c.id)}
							<tr>
								<td class="px-3 py-2 font-mono text-xs whitespace-nowrap"
									><a href="{resolve('/(app)/intelligence')}?cve={c.id}" class="hover:underline"
										>{c.id}</a
									></td
								>
								<td class="px-3 py-2 text-xs tabular-nums">{c.cvss_score ?? '—'}</td>
								<td class="px-3 py-2 text-xs tabular-nums">{pct(c.epss)}</td>
								<td class="px-3 py-2 text-xs">{c.kev ? 'Yes' : '—'}</td>
								<td class="px-3 py-2 text-xs text-slate-700"
									>{c.description.slice(0, 200)}{c.description.length > 200 ? '…' : ''}</td
								>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
	<p class="mt-6 text-xs text-slate-500">
		{data.notice} KEV data: CISA. EPSS data: FIRST (first.org/epss).
	</p>
{/if}
