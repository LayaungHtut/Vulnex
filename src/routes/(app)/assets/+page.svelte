<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import Notice from '#lib/components/Notice.svelte';
	import ScopeStatus from '#lib/components/ScopeStatus.svelte';
	import { CRITICALITIES, can } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const f = $derived(data.filters);
	const manage = $derived(can(data.session, 'assets.manage'));
	const pages = $derived(Math.max(1, Math.ceil(data.assets.total / data.pageSize)));
	const filtered = $derived(
		Boolean(f.q || f.criticality || f.scope_group_id || f.status !== 'active')
	);
	const pageHref = (page: number) => {
		// Only non-default filters go in the URL.
		const qs = Object.entries({ ...f, page: String(page) })
			.filter(([k, v]) => v && !(k === 'status' && v === 'active') && !(k === 'page' && v === '1'))
			.map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
			.join('&');
		return resolve(qs ? `/(app)/assets?${qs}` : '/(app)/assets');
	};
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>Assets · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Assets</h1>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	Addresses, ranges and hostnames registered for assessment. Each belongs to a scope group and is
	scanned only while it lies inside that group and the group is authorized.
</p>

<Notice message={form?.message} success={form?.success} />

<form method="GET" class="mt-6 flex flex-wrap items-end gap-3" data-sveltekit-keepfocus>
	<label class="block text-sm">
		<span class="text-xs font-medium text-slate-600">Search</span>
		<input name="q" value={f.q} maxlength="100" placeholder="Target or name" class="{input} w-56" />
	</label>
	<label class="block text-sm">
		<span class="text-xs font-medium text-slate-600">Status</span>
		<select name="status" value={f.status} class={input}>
			<option value="active">Active</option>
			<option value="retired">Retired</option>
			<option value="all">All</option>
		</select>
	</label>
	<label class="block text-sm">
		<span class="text-xs font-medium text-slate-600">Criticality</span>
		<select name="criticality" value={f.criticality} class="{input} capitalize">
			<option value="">Any</option>
			{#each CRITICALITIES as c (c)}<option value={c}>{c}</option>{/each}
		</select>
	</label>
	{#if data.groups.length}
		<label class="block text-sm">
			<span class="text-xs font-medium text-slate-600">Scope group</span>
			<select name="scope_group_id" value={f.scope_group_id} class={input}>
				<option value="">Any</option>
				{#each data.groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
			</select>
		</label>
	{/if}
	<button class="rounded border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-50"
		>Apply</button
	>
	{#if filtered}
		<a href={resolve('/(app)/assets')} class="py-2 text-sm text-slate-600 hover:underline">Clear</a>
	{/if}
</form>

{#if data.loadError}
	<Notice message="Assets could not be loaded: {data.loadError}" />
{:else if data.assets.total === 0}
	<p
		class="mt-4 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
	>
		{#if filtered}
			No assets match these filters.
		{:else if manage && data.groups.length === 0}
			No assets yet. First <a href={resolve('/(app)/scope')} class="underline"
				>define an authorized scope</a
			>, then register the assets inside it.
		{:else if manage}
			No assets yet. Register one below.
		{:else}
			No assets have been registered yet.
		{/if}
	</p>
{:else}
	<div class="mt-4 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium">Target</th>
					<th scope="col" class="px-4 py-2 font-medium">Scope group</th>
					<th scope="col" class="px-4 py-2 font-medium">Criticality</th>
					<th scope="col" class="px-4 py-2 font-medium">Scan eligibility</th>
					<th scope="col" class="px-4 py-2 font-medium">Last seen</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.assets.items as a (a.id)}
					<tr class={a.status === 'retired' ? 'text-slate-500' : ''}>
						<td class="px-4 py-2.5">
							<a
								href={resolve('/(app)/assets/[id]', { id: a.id })}
								class="font-mono text-[13px] font-medium hover:underline">{a.target}</a
							>
							{#if a.status === 'retired'}<span class="ml-1 text-xs">· retired</span>{/if}
							{#if a.name}<div class="text-xs text-slate-500">{a.name}</div>{/if}
						</td>
						<td class="px-4 py-2.5">{a.scope_group_name}</td>
						<td class="px-4 py-2.5 capitalize">{a.criticality}</td>
						<td class="px-4 py-2.5"><ScopeStatus scope={a.scope} /></td>
						<!-- Set by scans from M5; until then no asset has been observed. -->
						<td class="px-4 py-2.5 text-slate-500">
							{a.last_seen_at ? new Date(a.last_seen_at).toLocaleDateString() : 'Never scanned'}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<div class="mt-3 flex items-center justify-between text-sm text-slate-600">
		<span>{data.assets.total} asset{data.assets.total === 1 ? '' : 's'}</span>
		{#if pages > 1}
			<nav aria-label="Pages" class="flex items-center gap-3">
				{#if f.page > 1}<a href={pageHref(f.page - 1)} class="hover:underline">Previous</a>{/if}
				<span>Page {f.page} of {pages}</span>
				{#if f.page < pages}<a href={pageHref(f.page + 1)} class="hover:underline">Next</a>{/if}
			</nav>
		{/if}
	</div>
{/if}

{#if manage && data.groups.length}
	<section aria-labelledby="add" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="add" class="text-sm font-medium">Register an asset</h2>
		<p class="mt-1 text-xs text-slate-500">
			An IPv4 address, a range up to /20 (4,096 addresses), or a fully qualified hostname. It must
			lie inside the chosen scope group.
		</p>
		<form method="POST" action="?/add" use:enhance class="mt-4 grid gap-4 sm:grid-cols-2">
			<label class="block text-sm">
				<span class="font-medium">Target</span>
				<input
					name="target"
					required
					maxlength="260"
					class="{input} font-mono"
					placeholder="192.0.2.10, 10.0.4.0/24, app.example.com"
					autocomplete="off"
					spellcheck="false"
					value={form?.values?.target ?? ''}
				/>
			</label>
			<label class="block text-sm">
				<span class="font-medium">Scope group</span>
				<select
					name="scope_group_id"
					required
					class={input}
					value={form?.values?.scope_group_id || f.scope_group_id || data.groups[0].id}
				>
					{#each data.groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
				</select>
			</label>
			<label class="block text-sm">
				<span class="font-medium">Name <span class="text-slate-500">(optional)</span></span>
				<input name="name" maxlength="100" class={input} value={form?.values?.name ?? ''} />
			</label>
			<label class="block text-sm">
				<span class="font-medium">Criticality</span>
				<select
					name="criticality"
					class="{input} capitalize"
					value={form?.values?.criticality ?? 'medium'}
				>
					{#each CRITICALITIES as c (c)}<option value={c}>{c}</option>{/each}
				</select>
			</label>
			<div class="sm:col-span-2">
				<button
					class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
					>Register asset</button
				>
			</div>
		</form>
	</section>
{/if}
