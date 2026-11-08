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
	<h1 class="text-xl font-semibold tracking-tight">
		{s.profile === 'discovery' ? 'Discovery scan' : 'Scope check'}
	</h1>
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
	{#if s.profile === 'discovery'}
		<div class="sm:col-span-3">
			<dt class="text-xs text-slate-500">Ports ({s.ports.length})</dt>
			<dd class="font-mono text-xs break-words">{s.ports.join(', ')}</dd>
		</div>
	{/if}
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

{#if s.summary}
	{@const m = s.summary}
	<section aria-labelledby="summary" class="mt-8">
		<h2 id="summary" class="text-sm font-medium">Results</h2>
		{#if m.stopped}
			<p class="mt-2 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
				The scan stopped early ({m.stopped}). Ports it did not reach are not marked closed, and no
				finding was resolved by a check that did not run.
			</p>
		{/if}
		<dl class="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
			{#each [['Hosts probed', m.hosts_probed], ['Hosts responding', m.hosts_responding], ['Open ports', m.open_ports], ['New services', m.services_new], ['Services closed', m.services_closed], ['New findings', m.findings?.new ?? 0], ['Verified resolved', m.findings?.resolved ?? 0], ['Reopened', m.findings?.reopened ?? 0]] as [k, v] (k)}
				<div class="rounded-md border border-slate-200 bg-white px-3 py-2">
					<dt class="text-xs text-slate-500">{k}</dt>
					<dd class="text-lg font-semibold tabular-nums">{v}</dd>
				</div>
			{/each}
		</dl>
		<p class="mt-2 text-xs text-slate-500">
			{m.probes.toLocaleString()} probes · scanner {m.scanner_version}{m.dropped
				? ` · ${m.dropped} observation(s) outside the scan's targets were discarded`
				: ''}{m.refused_targets.length ? ` · refused: ${m.refused_targets.join('; ')}` : ''}
		</p>
		{#if can(data.session, 'findings.read') && (m.findings?.new ?? 0) + (m.findings?.updated ?? 0) > 0}
			<p class="mt-2 text-sm">
				<a href={resolve('/(app)/findings')} class="underline">View findings</a>
			</p>
		{/if}
	</section>
{/if}

{#if data.evidence?.length}
	<section aria-labelledby="evidence" class="mt-6">
		<h2 id="evidence" class="text-sm font-medium">Observations ({data.evidence.length})</h2>
		<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-slate-200 text-xs text-slate-500">
					<tr>
						<th scope="col" class="px-4 py-2 font-medium">Address</th>
						<th scope="col" class="px-4 py-2 font-medium">Port</th>
						<th scope="col" class="px-4 py-2 font-medium">Banner / response</th>
						<th scope="col" class="px-4 py-2 font-medium">Observed</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-slate-100">
					{#each data.evidence.filter((e) => e.kind === 'service') as e (e.id)}
						{@const d = e.data as {
							banner?: string;
							probe_reply?: string;
							http?: { status?: number; headers?: [string, string][] };
							tls?: { certificate?: { subject?: string } };
						}}
						<tr class="align-top">
							<td class="px-4 py-2 font-mono text-xs">{e.address}</td>
							<td class="px-4 py-2 font-mono text-xs">{e.port}</td>
							<td class="max-w-lg truncate px-4 py-2 font-mono text-xs text-slate-700">
								{d.banner?.trim() ||
									d.probe_reply?.trim() ||
									(d.http
										? `HTTP ${d.http.status ?? ''} ${d.http.headers?.find(([k]) => k.toLowerCase() === 'server')?.[1] ?? ''}`
										: '') ||
									(d.tls?.certificate?.subject ? `TLS ${d.tls.certificate.subject}` : '—')}
							</td>
							<td class="px-4 py-2 text-xs whitespace-nowrap text-slate-600"
								>{when(e.observed_at)}</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</section>
{/if}

{#if s.result && s.profile === 'scope_check'}
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
