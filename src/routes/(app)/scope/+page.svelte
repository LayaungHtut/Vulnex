<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import AuthorizationBadge from '#lib/components/AuthorizationBadge.svelte';
	import Notice from '#lib/components/Notice.svelte';
	import { can } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const manage = $derived(can(data.session, 'scope.manage'));
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>Authorized scope · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Authorized scope</h1>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	A scope group is the boundary VULNEX may assess: the ranges and hostnames
	{data.session.organization.name} owns or has written permission to test. Assets must lie inside a scope
	group, and a group must be authorized by an owner or administrator before anything in it is scanned.
	Loopback, link-local (including cloud metadata), multicast and reserved addresses are never accepted.
</p>

<Notice message={form?.message} />

{#if data.loadError}
	<Notice message="Scope groups could not be loaded: {data.loadError}" />
{:else if data.groups.length === 0}
	<p
		class="mt-6 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
	>
		No scope groups yet.
		{manage
			? 'Create one below, add the ranges and hostnames you are authorized to assess, then authorize it.'
			: 'An owner or administrator defines what may be assessed.'}
	</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium">Scope group</th>
					<th scope="col" class="px-4 py-2 font-medium">Authorization</th>
					<th scope="col" class="px-4 py-2 text-right font-medium">Entries</th>
					<th scope="col" class="px-4 py-2 text-right font-medium">Active assets</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.groups as g (g.id)}
					<tr>
						<td class="px-4 py-2.5">
							<a
								href={resolve('/(app)/scope/[id]', { id: g.id })}
								class="font-medium hover:underline">{g.name}</a
							>
							{#if g.description}<div class="text-xs text-slate-500">{g.description}</div>{/if}
						</td>
						<td class="px-4 py-2.5"><AuthorizationBadge status={g.authorization.status} /></td>
						<td class="px-4 py-2.5 text-right tabular-nums">
							{g.entries.filter((e) => !e.exclude).length} included
							{#if g.entries.some((e) => e.exclude)}
								<span class="text-slate-500"
									>· {g.entries.filter((e) => e.exclude).length} excluded</span
								>
							{/if}
						</td>
						<td class="px-4 py-2.5 text-right tabular-nums">{g.active_assets}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if manage}
	<section aria-labelledby="create" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="create" class="text-sm font-medium">New scope group</h2>
		<form method="POST" action="?/create" use:enhance class="mt-4 grid gap-4 sm:grid-cols-2">
			<label class="block text-sm">
				<span class="font-medium">Name</span>
				<input name="name" required maxlength="100" class={input} placeholder="Head office LAN" />
			</label>
			<label class="block text-sm">
				<span class="font-medium">Description <span class="text-slate-500">(optional)</span></span>
				<input
					name="description"
					maxlength="1000"
					class={input}
					placeholder="Basis of authorization, owner, ticket"
				/>
			</label>
			<div class="sm:col-span-2">
				<button
					class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
					>Create scope group</button
				>
			</div>
		</form>
	</section>
{/if}
