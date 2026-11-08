<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import Notice from '#lib/components/Notice.svelte';
	import ConfidenceBadge from '#lib/components/ConfidenceBadge.svelte';
	import ScopeStatus from '#lib/components/ScopeStatus.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import { CRITICALITIES, can } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const a = $derived(data.asset);
	const manage = $derived(can(data.session, 'assets.manage'));
	const when = (iso: string | null) =>
		iso
			? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
			: '—';
	const kind = { ip: 'IPv4 address', cidr: 'IPv4 range', hostname: 'Hostname' };
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>{a.target} · Assets · VULNEX</title></svelte:head>

<p class="text-sm">
	<a href={resolve('/(app)/assets')} class="text-slate-600 hover:underline">Assets</a>
</p>
<div class="mt-1 flex flex-wrap items-baseline gap-3">
	<h1 class="font-mono text-xl font-semibold tracking-tight">{a.target}</h1>
	{#if a.name}<span class="text-slate-600">{a.name}</span>{/if}
	{#if a.status === 'retired'}
		<span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700 ring-1 ring-slate-200"
			>Retired</span
		>
	{/if}
</div>

<Notice message={form?.message} success={form?.success} />

<dl
	class="mt-6 grid gap-x-8 gap-y-3 rounded-md border border-slate-200 bg-white p-4 text-sm sm:grid-cols-3"
>
	<div>
		<dt class="text-xs text-slate-500">Type</dt>
		<dd>{kind[a.kind]}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Scope group</dt>
		<dd>
			{#if can(data.session, 'scope.read')}
				<a href={resolve('/(app)/scope/[id]', { id: a.scope_group_id })} class="hover:underline"
					>{a.scope_group_name}</a
				>
			{:else}
				{a.scope_group_name}
			{/if}
		</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Scan eligibility</dt>
		<dd><ScopeStatus scope={a.scope} /></dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Criticality</dt>
		<dd class="capitalize">{a.criticality}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Source</dt>
		<dd>{a.source === 'user' ? 'Registered by a user' : 'Discovered'}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Registered</dt>
		<dd>{when(a.created_at)}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">First seen / last seen</dt>
		<dd>
			{a.first_seen_at ? `${when(a.first_seen_at)} / ${when(a.last_seen_at)}` : 'Never scanned'}
		</dd>
	</div>
	{#if a.retired_at}
		<div>
			<dt class="text-xs text-slate-500">Retired</dt>
			<dd>{when(a.retired_at)}</dd>
		</div>
	{/if}
	{#if a.notes && !manage}
		<div class="sm:col-span-3">
			<dt class="text-xs text-slate-500">Notes</dt>
			<dd class="whitespace-pre-line">{a.notes}</dd>
		</div>
	{/if}
</dl>

{#if a.scope.problem}
	<p class="mt-4 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
		Out of scope: {a.scope.problem}. Its scope group changed after this asset was registered; it
		will not be scanned until the scope covers it again.
	</p>
{:else if !a.scope.authorized && a.status === 'active'}
	<p class="mt-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
		The scope group "{a.scope_group_name}" is not currently authorized, so this asset will not be
		scanned.
	</p>
{/if}

{#if can(data.session, 'scans.run') && a.status === 'active' && a.scope.in_scope && a.scope.authorized}
	<form method="POST" action="?/scan" use:enhance class="mt-4 flex flex-wrap items-center gap-3">
		<label class="sr-only" for="profile">Scan profile</label>
		<select id="profile" name="profile" class="rounded border-slate-300 text-sm">
			<option value="discovery">Discovery: ports, services, TLS, findings</option>
			<option value="scope_check">Scope check only (no traffic to the target)</option>
		</select>
		<button class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
			>Run scan</button
		>
		<span class="text-sm text-slate-500"
			>Runs on a scanner of "{a.scope_group_name}", which re-checks the signed scope before every
			connection. Discovery uses non-intrusive TCP connects and read-only probes.</span
		>
	</form>
{/if}

{#if data.findings && data.findings.total > 0}
	<section aria-labelledby="findings" class="mt-8">
		<div class="flex items-baseline justify-between">
			<h2 id="findings" class="text-sm font-medium">Active findings ({data.findings.total})</h2>
			<a href="{resolve('/(app)/findings')}?asset_id={a.id}" class="text-xs underline"
				>All findings for this asset</a
			>
		</div>
		<ul class="mt-2 divide-y divide-slate-100 rounded-md border border-slate-200 bg-white text-sm">
			{#each data.findings.items as f (f.id)}
				<li class="flex flex-wrap items-center gap-3 px-4 py-2">
					<SeverityBadge level={f.risk_band} score={f.risk_score} />
					<a
						href={resolve('/(app)/findings/[id]', { id: f.id })}
						class="min-w-0 flex-1 hover:underline">{f.title}</a
					>
					<span class="font-mono text-xs text-slate-500"
						>{f.address}{f.port ? `:${f.port}` : ''}</span
					>
					<ConfidenceBadge confidence={f.confidence} />
				</li>
			{/each}
		</ul>
	</section>
{/if}

<section aria-labelledby="services" class="mt-8">
	<h2 id="services" class="text-sm font-medium">Services</h2>
	{#if !data.services}
		<p class="mt-2 text-sm text-slate-500">Services could not be loaded.</p>
	{:else if data.services.total === 0}
		<p class="mt-2 text-sm text-slate-500">
			No open services recorded. Run a discovery scan to find them.
		</p>
	{:else}
		<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-slate-200 text-xs text-slate-500">
					<tr>
						<th scope="col" class="px-4 py-2 font-medium">Address</th>
						<th scope="col" class="px-4 py-2 font-medium">Port</th>
						<th scope="col" class="px-4 py-2 font-medium">Service</th>
						<th scope="col" class="px-4 py-2 font-medium">Product</th>
						<th scope="col" class="px-4 py-2 font-medium">Identified by</th>
						<th scope="col" class="px-4 py-2 font-medium">Last seen</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-slate-100">
					{#each data.services.items as svc (svc.id)}
						<tr>
							<td class="px-4 py-2 font-mono text-xs">{svc.address}</td>
							<td class="px-4 py-2 font-mono text-xs"
								>{svc.port}/{svc.transport}{svc.tls ? ' · TLS' : ''}</td
							>
							<td class="px-4 py-2">{svc.name ?? 'unknown'}</td>
							<td class="px-4 py-2"
								>{[svc.product, svc.version].filter(Boolean).join(' ') || '—'}</td
							>
							<td
								class="px-4 py-2 text-xs text-slate-500"
								title="Port-number guesses are the weakest evidence"
								>{svc.fingerprint_method ?? '—'}</td
							>
							<td class="px-4 py-2 text-xs text-slate-600">{when(svc.last_seen_at)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>

{#if manage}
	<section aria-labelledby="edit" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="edit" class="text-sm font-medium">Details</h2>
		<form method="POST" action="?/update" use:enhance class="mt-4 grid gap-4 sm:grid-cols-2">
			<label class="block text-sm">
				<span class="font-medium">Name</span>
				<input name="name" maxlength="100" class={input} value={a.name} />
			</label>
			<label class="block text-sm">
				<span class="font-medium">Criticality</span>
				<select name="criticality" class="{input} capitalize" value={a.criticality}>
					{#each CRITICALITIES as c (c)}<option value={c}>{c}</option>{/each}
				</select>
			</label>
			<label class="block text-sm sm:col-span-2">
				<span class="font-medium">Notes</span>
				<textarea name="notes" maxlength="2000" rows="3" class={input}>{a.notes}</textarea>
			</label>
			<div class="sm:col-span-2">
				<button
					class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
					>Save</button
				>
			</div>
		</form>
		<div class="mt-4 border-t border-slate-100 pt-4">
			{#if a.status === 'active'}
				<form
					method="POST"
					action="?/retire"
					use:enhance={({ cancel }) => {
						if (!confirm(`Retire ${a.target}? It will no longer be scanned.`)) cancel();
					}}
				>
					<button class="text-sm text-red-700 hover:underline">Retire asset</button>
					<span class="ml-2 text-xs text-slate-500">Stops assessment; history is kept.</span>
				</form>
			{:else}
				<form method="POST" action="?/reactivate" use:enhance>
					<button class="rounded border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50"
						>Reactivate asset</button
					>
				</form>
			{/if}
		</div>
	</section>
{/if}

{#if data.history || data.historyError}
	<section aria-labelledby="history" class="mt-8">
		<h2 id="history" class="text-sm font-medium">History</h2>
		{#if data.historyError}
			<Notice message="History could not be loaded: {data.historyError}" />
		{:else if data.history}
			<ol
				class="mt-2 divide-y divide-slate-100 rounded-md border border-slate-200 bg-white text-sm"
			>
				{#each data.history.items as e (e.id)}
					<li class="flex flex-wrap justify-between gap-2 px-4 py-2">
						<span
							><code class="text-[13px]">{e.action}</code> by {e.actor_email ??
								'a former member'}</span
						>
						<span class="text-slate-500">{when(e.occurred_at)}</span>
					</li>
				{/each}
			</ol>
		{/if}
	</section>
{/if}
