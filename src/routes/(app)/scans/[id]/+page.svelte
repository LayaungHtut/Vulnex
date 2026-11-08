<script lang="ts">
	import { enhance } from '$app/forms';
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import Notice from '#lib/components/Notice.svelte';
	import ScanStateBadge from '#lib/components/ScanStateBadge.svelte';
	import { can } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const s = $derived(data.scan);
	const active = $derived(s.state === 'queued' || s.state === 'running');
	const when = (iso: string | null) =>
		iso
			? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
			: '—';

	// Reload from the API while the scan is in progress; stop once it has finished.
	$effect(() => {
		if (!active) return;
		const timer = setInterval(() => invalidateAll(), 3000);
		return () => clearInterval(timer);
	});
</script>

<svelte:head><title>Scan · VULNEX</title></svelte:head>

<p class="text-sm">
	<a href={resolve('/(app)/scans')} class="text-slate-600 hover:underline">Scans</a>
</p>
<div class="mt-1 flex flex-wrap items-baseline gap-3">
	<h1 class="text-xl font-semibold tracking-tight">Scope check</h1>
	<ScanStateBadge state={s.state} cancelRequested={s.cancel_requested} />
</div>

<Notice message={form?.message} success={form?.success} />

<dl
	class="mt-6 grid gap-x-8 gap-y-3 rounded-md border border-slate-200 bg-white p-4 text-sm sm:grid-cols-3"
>
	<div>
		<dt class="text-xs text-slate-500">Scope group</dt>
		<dd>
			<a href={resolve('/(app)/scope/[id]', { id: s.scope_group_id })} class="hover:underline"
				>{s.scope_group_name}</a
			>
		</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Requested</dt>
		<dd>{when(s.created_at)} · {s.requested_by_email ?? '—'}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Finished</dt>
		<dd>{when(s.finished_at)}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Attempt</dt>
		<dd>{s.attempt} of {s.max_attempts}</dd>
	</div>
	<div class="sm:col-span-2">
		<dt class="text-xs text-slate-500">Targets</dt>
		<dd class="font-mono text-xs">{s.targets.join(', ')}</dd>
	</div>
</dl>

{#if s.last_error}
	<p class="mt-4 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
		{s.state === 'queued' ? 'Last attempt ended: ' : ''}{s.last_error}
	</p>
{/if}

{#if s.state === 'queued'}
	<p class="mt-4 text-sm text-slate-600">
		Waiting for a scanner of “{s.scope_group_name}”. If none is online, see
		<a href={resolve('/(app)/workers')} class="underline">Scanners</a>.
	</p>
{/if}

{#if active && can(data.session, 'scans.run') && !s.cancel_requested}
	<form method="POST" action="?/cancel" use:enhance class="mt-4">
		<button
			class="rounded border border-slate-300 bg-white px-3 py-2 text-sm font-medium hover:bg-slate-50"
			>Cancel scan</button
		>
	</form>
{/if}

{#if s.result}
	<section aria-labelledby="result" class="mt-8">
		<h2 id="result" class="text-sm font-medium">Scanner report</h2>
		{#if s.result.allowed?.length}
			<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
				<table class="w-full text-left text-sm">
					<caption class="px-4 pt-3 text-left text-xs text-slate-500"
						>Within the signed scope: the scanner may assess these</caption
					>
					<thead class="border-b border-slate-200 text-xs text-slate-500">
						<tr>
							<th scope="col" class="px-4 py-2 font-medium">Target</th>
							<th scope="col" class="px-4 py-2 text-right font-medium">Addresses</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-slate-100">
						{#each s.result.allowed as a (a.target)}
							<tr>
								<td class="px-4 py-2 font-mono text-xs">{a.target}</td>
								<td class="px-4 py-2 text-right tabular-nums"
									>{a.addresses ?? 'resolved at scan time'}</td
								>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
		{#if s.result.refused?.length}
			<div class="mt-3 overflow-x-auto rounded-md border border-red-200 bg-white">
				<table class="w-full text-left text-sm">
					<caption class="px-4 pt-3 text-left text-xs text-red-800">Refused by the scanner</caption>
					<thead class="border-b border-slate-200 text-xs text-slate-500">
						<tr>
							<th scope="col" class="px-4 py-2 font-medium">Target</th>
							<th scope="col" class="px-4 py-2 font-medium">Reason</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-slate-100">
						{#each s.result.refused as r (r.target)}
							<tr>
								<td class="px-4 py-2 font-mono text-xs">{r.target}</td>
								<td class="px-4 py-2">{r.reason}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
		{#if !s.result.allowed?.length && !s.result.refused?.length}
			<p class="mt-2 text-sm text-slate-600">The scanner returned no target report.</p>
		{/if}
	</section>
{/if}
