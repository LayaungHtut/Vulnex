<script lang="ts">
	import { resolve } from '$app/paths';
	import type { AuditEvent } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const time = (iso: string) =>
		new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
	const detail = (e: AuditEvent) =>
		Object.entries(e.detail)
			.map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
			.join(' · ');
</script>

<svelte:head><title>Audit log · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Audit log</h1>
<p class="mt-1 text-sm text-slate-600">
	Security-relevant actions in {data.session.organization.name}, newest first. Entries cannot be
	edited or deleted through VULNEX.
</p>

{#if data.loadError}
	<p
		role="alert"
		class="mt-6 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
	>
		The audit log could not be loaded: {data.loadError}
	</p>
{:else if data.page.items.length === 0}
	<p class="mt-6 text-sm text-slate-600">
		{data.paged ? 'No older events.' : 'No events recorded yet.'}
	</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium whitespace-nowrap">Time</th>
					<th scope="col" class="px-4 py-2 font-medium">Actor</th>
					<th scope="col" class="px-4 py-2 font-medium">Action</th>
					<th scope="col" class="px-4 py-2 font-medium">Details</th>
					<th scope="col" class="px-4 py-2 font-medium">Source</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100 align-top">
				{#each data.page.items as e (e.id)}
					<tr>
						<td class="px-4 py-2 whitespace-nowrap text-slate-600">
							<time datetime={e.occurred_at}>{time(e.occurred_at)}</time>
						</td>
						<td class="px-4 py-2">
							{e.actor_email ?? (e.actor_user_id ? 'Former member' : 'System')}
						</td>
						<td class="px-4 py-2 font-mono text-xs">{e.action}</td>
						<td class="px-4 py-2 text-xs text-slate-600">
							{#if e.target_type}<div>{e.target_type} {e.target_id}</div>{/if}
							{#if Object.keys(e.detail).length}<div>{detail(e)}</div>{/if}
						</td>
						<td class="px-4 py-2 text-xs text-slate-500">
							<div>{e.ip ?? '—'}</div>
							{#if e.request_id}<div class="font-mono" title="Request ID">{e.request_id}</div>{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<nav aria-label="Audit log pages" class="mt-4 flex gap-4 text-sm">
	{#if data.paged}<a href={resolve('audit')} class="text-slate-700 hover:underline">Newest</a>{/if}
	{#if data.page.next_before_id}
		<a
			href={resolve(`audit?before=${data.page.next_before_id}`)}
			class="text-slate-700 hover:underline">Older events →</a
		>
	{/if}
</nav>
