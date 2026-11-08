<script lang="ts">
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import ConfidenceBadge from '#lib/components/ConfidenceBadge.svelte';
	import Notice from '#lib/components/Notice.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import { STATUS_LABEL, type FindingStatus } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const params = $derived(page.url.searchParams);
	const statusFilter = $derived(params.has('status') ? (params.get('status') ?? '') : 'active');
	const offset = $derived(Number(params.get('offset') ?? 0) || 0);
	const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
	const statuses: [string, string][] = [
		['active', 'Active (not closed)'],
		...(Object.entries(STATUS_LABEL) as [FindingStatus, string][]),
		['', 'Any status']
	];
	const select =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
	const pageQuery = (to: number) =>
		new URLSearchParams([
			...[...params].filter(([k]) => k !== 'offset'),
			['offset', String(Math.max(0, to))]
		]).toString();
</script>

<svelte:head><title>Findings · VULNEX</title></svelte:head>

<div class="flex flex-wrap items-baseline justify-between gap-3">
	<h1 class="text-xl font-semibold tracking-tight">Findings</h1>
	<!-- eslint-disable svelte/no-navigation-without-resolve -- a file download, not a page -->
	<a
		href="{resolve('/(app)/findings')}/export.csv?{data.query}"
		data-sveltekit-reload
		class="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
		>Export CSV</a
	>
	<!-- eslint-enable svelte/no-navigation-without-resolve -->
</div>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	Ordered by priority (risk score). <strong>Confirmed</strong> means the condition itself was
	observed; <strong>potential</strong> means a version match only, which a vendor backport may already
	fix. A finding is resolved only when a later scan runs the same check and no longer finds the condition.
</p>

<form
	method="GET"
	class="mt-5 grid gap-3 rounded-md border border-slate-200 bg-white p-3 sm:grid-cols-6"
>
	<label class="text-xs text-slate-600 sm:col-span-2">
		Search
		<input
			name="q"
			value={params.get('q') ?? ''}
			placeholder="Title, CVE, address, asset"
			maxlength="100"
			class={select}
		/>
	</label>
	<label class="text-xs text-slate-600">
		Status
		<select name="status" class={select}>
			{#each statuses as [value, label] (value)}
				<option {value} selected={statusFilter === value}>{label}</option>
			{/each}
		</select>
	</label>
	<label class="text-xs text-slate-600">
		Priority
		<select name="band" class={select}>
			<option value="">Any</option>
			{#each ['urgent', 'high', 'medium', 'low'] as b (b)}
				<option value={b} selected={params.get('band') === b} class="capitalize">{b}</option>
			{/each}
		</select>
	</label>
	<label class="text-xs text-slate-600">
		Confidence
		<select name="confidence" class={select}>
			<option value="">Any</option>
			{#each ['confirmed', 'probable', 'potential'] as c (c)}
				<option value={c} selected={params.get('confidence') === c} class="capitalize">{c}</option>
			{/each}
		</select>
	</label>
	<div class="flex items-end gap-3">
		<label class="flex items-center gap-1.5 pb-2 text-xs text-slate-600">
			<input type="checkbox" name="kev" value="true" checked={params.get('kev') === 'true'} />
			KEV only
		</label>
		<button class="mb-0.5 rounded bg-slate-900 px-3 py-1.5 text-sm font-medium text-white"
			>Apply</button
		>
	</div>
</form>

{#if data.loadError}
	<Notice message="Findings could not be loaded: {data.loadError}" />
{:else if data.page.total === 0}
	<p
		class="mt-6 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
	>
		{#if params.size > 0}
			No findings match these filters.
		{:else}
			No active findings. Findings appear after a <em>discovery</em> scan of an asset; run one from the
			asset's page.
		{/if}
	</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-3 py-2 font-medium">Priority</th>
					<th scope="col" class="px-3 py-2 font-medium">Finding</th>
					<th scope="col" class="px-3 py-2 font-medium">Where</th>
					<th scope="col" class="px-3 py-2 font-medium">Severity</th>
					<th scope="col" class="px-3 py-2 font-medium">Confidence</th>
					<th scope="col" class="px-3 py-2 font-medium">Status</th>
					<th scope="col" class="px-3 py-2 font-medium">First seen</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.page.items as f (f.id)}
					<tr class="align-top">
						<td class="px-3 py-2.5"><SeverityBadge level={f.risk_band} score={f.risk_score} /></td>
						<td class="max-w-md px-3 py-2.5">
							<a
								href={resolve('/(app)/findings/[id]', { id: f.id })}
								class="font-medium hover:underline">{f.title}</a
							>
							<div class="mt-0.5 flex flex-wrap gap-x-2 text-xs text-slate-500">
								{#if f.kev}<span class="font-semibold text-red-700">Known exploited (KEV)</span
									>{/if}
								{#if f.cves.length}<span class="font-mono"
										>{f.cves.slice(0, 2).join(', ')}{f.cves.length > 2
											? ` +${f.cves.length - 2}`
											: ''}</span
									>{/if}
								{#if f.overdue}<span class="text-red-700">Overdue</span>{/if}
								{#if f.not_observed_since}<span title="The check could not run in the latest scan"
										>Not observed recently</span
									>{/if}
							</div>
						</td>
						<td class="px-3 py-2.5 font-mono text-xs whitespace-nowrap">
							{f.address ?? f.asset_target}{f.port ? `:${f.port}` : ''}
							{#if f.asset_name}<div class="font-sans text-slate-500">{f.asset_name}</div>{/if}
						</td>
						<td class="px-3 py-2.5"><SeverityBadge level={f.severity} /></td>
						<td class="px-3 py-2.5"><ConfidenceBadge confidence={f.confidence} /></td>
						<td class="px-3 py-2.5 text-xs whitespace-nowrap">
							{STATUS_LABEL[f.status]}
							{#if f.assignee_email}<div class="text-slate-500">{f.assignee_email}</div>{/if}
						</td>
						<td class="px-3 py-2.5 text-xs whitespace-nowrap text-slate-600"
							>{day(f.first_seen_at)}</td
						>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<nav aria-label="Pages" class="mt-2 flex items-center justify-between text-xs text-slate-500">
		<span>
			{offset + 1}–{offset + data.page.items.length} of {data.page.total}
		</span>
		<span class="flex gap-3">
			{#if offset > 0}<a
					href="{resolve('/(app)/findings')}?{pageQuery(offset - 50)}"
					class="underline">Previous</a
				>{/if}
			{#if offset + data.page.items.length < data.page.total}
				<a href="{resolve('/(app)/findings')}?{pageQuery(offset + 50)}" class="underline">Next</a>
			{/if}
		</span>
	</nav>
{/if}
