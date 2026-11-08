<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import AuthorizationBadge from '#lib/components/AuthorizationBadge.svelte';
	import Notice from '#lib/components/Notice.svelte';
	import { can, type ScopeEntry } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const g = $derived(data.group);
	const manage = $derived(can(data.session, 'scope.manage'));
	const auth = $derived(g.authorization);
	const kind: Record<ScopeEntry['kind'], string> = {
		cidr: 'Range',
		hostname: 'Hostname',
		hostname_wildcard: 'Subdomains'
	};
	const shown = (e: ScopeEntry) =>
		e.kind === 'hostname_wildcard'
			? `*.${e.value}`
			: e.value.endsWith('/32')
				? e.value.slice(0, -3)
				: e.value;
	const when = (iso: string) =>
		new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
	const button = 'rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800';
</script>

<svelte:head><title>{g.name} · Authorized scope · VULNEX</title></svelte:head>

<p class="text-sm">
	<a href={resolve('/(app)/scope')} class="text-slate-600 hover:underline">Authorized scope</a>
</p>
<div class="mt-1 flex flex-wrap items-center gap-3">
	<h1 class="text-xl font-semibold tracking-tight">{g.name}</h1>
	<AuthorizationBadge status={auth.status} />
</div>
{#if g.description}<p class="mt-1 text-sm text-slate-600">{g.description}</p>{/if}

<Notice message={form?.message} success={form?.success} />

<section
	aria-labelledby="authorization"
	class="mt-6 rounded-md border border-slate-200 bg-white p-4"
>
	<h2 id="authorization" class="text-sm font-medium">Authorization</h2>
	{#if auth.status === 'not_authorized'}
		<p class="mt-1 text-sm text-slate-600">
			Not authorized. Nothing in this group will be scanned until an owner or administrator confirms
			that {data.session.organization.name} may assess every entry.
		</p>
	{:else}
		<p class="mt-1 text-sm text-slate-600">
			Authorized by {auth.authorized_by_email ?? 'a former member'} on
			{auth.authorized_at ? when(auth.authorized_at) : '—'}:
		</p>
		<blockquote class="mt-2 border-l-2 border-slate-300 pl-3 text-sm text-slate-700">
			{auth.statement}
		</blockquote>
		{#if auth.status === 'changed_since_authorization'}
			<p class="mt-3 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
				The entries changed after this authorization, so it no longer applies. Review the entries
				and authorize again before scanning.
			</p>
		{/if}
	{/if}

	{#if manage}
		<div class="mt-4 flex flex-wrap items-start gap-6">
			{#if auth.status !== 'authorized'}
				<form method="POST" action="?/authorize" use:enhance class="max-w-xl space-y-3">
					<label class="flex items-start gap-2 text-sm">
						<input
							type="checkbox"
							name="confirm"
							required
							class="mt-0.5 rounded border-slate-300"
						/>
						<span>
							I confirm that {data.session.organization.name} owns, or has explicit written permission
							to assess, every address and hostname included in this scope, and that assessing them does
							not breach any agreement or law.
						</span>
					</label>
					<button class={button}>Authorize scope</button>
				</form>
			{/if}
			{#if auth.status !== 'not_authorized'}
				<form
					method="POST"
					action="?/revoke"
					use:enhance={({ cancel }) => {
						if (
							!confirm('Withdraw the authorization? Scans of this scope will stop being allowed.')
						)
							cancel();
					}}
				>
					<button class="rounded border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50"
						>Withdraw authorization</button
					>
				</form>
			{/if}
		</div>
	{/if}
</section>

<section aria-labelledby="entries" class="mt-6">
	<h2 id="entries" class="text-sm font-medium">Entries</h2>
	{#if g.entries.length === 0}
		<p
			class="mt-2 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
		>
			No entries. Add the IPv4 ranges, addresses and hostnames this group covers.
		</p>
	{:else}
		<div class="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-white">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-slate-200 text-xs text-slate-500">
					<tr>
						<th scope="col" class="px-4 py-2 font-medium">Entry</th>
						<th scope="col" class="px-4 py-2 font-medium">Type</th>
						<th scope="col" class="px-4 py-2 font-medium">Note</th>
						{#if manage}<th scope="col" class="px-4 py-2"><span class="sr-only">Actions</span></th
							>{/if}
					</tr>
				</thead>
				<tbody class="divide-y divide-slate-100">
					{#each g.entries as e (e.id)}
						<tr>
							<td class="px-4 py-2.5 font-mono text-[13px]">
								{#if e.exclude}<span
										class="mr-1 rounded bg-red-50 px-1 font-sans text-xs text-red-800 ring-1 ring-red-200"
										>Exclude</span
									>{/if}
								{shown(e)}
							</td>
							<td class="px-4 py-2.5 text-slate-600">{kind[e.kind]}</td>
							<td class="px-4 py-2.5 text-slate-600">{e.note}</td>
							{#if manage}
								<td class="px-4 py-2.5 text-right">
									<form method="POST" action="?/removeEntry" use:enhance>
										<input type="hidden" name="entry_id" value={e.id} />
										<button
											class="text-xs text-red-700 hover:underline"
											aria-label="Remove {shown(e)}">Remove</button
										>
									</form>
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	{#if manage}
		<form
			method="POST"
			action="?/addEntry"
			use:enhance
			class="mt-4 grid gap-4 rounded-md border border-slate-200 bg-white p-4 sm:grid-cols-[2fr_2fr_auto]"
		>
			<label class="block text-sm">
				<span class="font-medium">Range, address or hostname</span>
				<input
					name="value"
					required
					maxlength="260"
					class="{input} font-mono"
					placeholder="10.0.0.0/16, 192.0.2.10, *.corp.example"
					autocomplete="off"
					spellcheck="false"
				/>
				<span class="mt-1 block text-xs text-slate-500">
					IPv4 only; ranges up to /8; <code>*.name</code> covers subdomains, not the name itself.
				</span>
			</label>
			<label class="block text-sm">
				<span class="font-medium">Note <span class="text-slate-500">(optional)</span></span>
				<input name="note" maxlength="200" class={input} placeholder="Who granted permission" />
			</label>
			<div class="flex flex-col justify-start gap-2 pt-6">
				<label class="flex items-center gap-2 text-sm">
					<input type="checkbox" name="exclude" class="rounded border-slate-300" /> Exclude
				</label>
				<button class={button}>Add entry</button>
			</div>
		</form>
	{/if}
</section>

<section aria-labelledby="assets" class="mt-6 text-sm text-slate-600">
	<h2 id="assets" class="text-sm font-medium text-slate-900">Assets</h2>
	<p class="mt-1">
		{g.active_assets} active, {g.retired_assets} retired.
		{#if can(data.session, 'assets.read')}
			<a href={resolve(`/(app)/assets?scope_group_id=${g.id}`)} class="text-slate-900 underline"
				>View assets</a
			>
		{/if}
	</p>
</section>

{#if manage}
	<section aria-labelledby="settings" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="settings" class="text-sm font-medium">Group details</h2>
		<form method="POST" action="?/update" use:enhance class="mt-4 grid gap-4 sm:grid-cols-2">
			<label class="block text-sm">
				<span class="font-medium">Name</span>
				<input name="name" required maxlength="100" class={input} value={g.name} />
			</label>
			<label class="block text-sm">
				<span class="font-medium">Description</span>
				<input name="description" maxlength="1000" class={input} value={g.description} />
			</label>
			<div class="flex flex-wrap items-center gap-4 sm:col-span-2">
				<button class={button}>Save</button>
			</div>
		</form>
		<form
			method="POST"
			action="?/delete"
			class="mt-4 border-t border-slate-100 pt-4"
			use:enhance={({ cancel }) => {
				if (!confirm(`Delete the scope group "${g.name}"?`)) cancel();
			}}
		>
			<button class="text-sm text-red-700 hover:underline">Delete scope group</button>
			<span class="ml-2 text-xs text-slate-500"
				>Only possible while it has no assets, active or retired.</span
			>
		</form>
	</section>
{/if}
