<script lang="ts">
	import { resolve } from '$app/paths';
	import Notice from '#lib/components/Notice.svelte';
	import ScanStateBadge from '#lib/components/ScanStateBadge.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const when = (iso: string) =>
		new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
</script>

<svelte:head><title>Scans · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Scans</h1>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	Scans run on your scanners, inside an authorized scope group, and each scanner re-checks the scope
	itself before acting. The current scan profile, <em>scope check</em>, reports which addresses a
	scanner may assess without sending any traffic to them. Start one from an asset.
</p>

{#if data.loadError}
	<Notice message="Scans could not be loaded: {data.loadError}" />
{:else if data.page.total === 0}
	<p
		class="mt-6 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
	>
		No scans yet. Open an asset in an authorized scope group and choose “Run scope check”. A scanner
		enrolled for that scope group must be running to pick it up.
	</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium">Requested</th>
					<th scope="col" class="px-4 py-2 font-medium">Targets</th>
					<th scope="col" class="px-4 py-2 font-medium">Scope group</th>
					<th scope="col" class="px-4 py-2 font-medium">State</th>
					<th scope="col" class="px-4 py-2 font-medium">By</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.page.items as s (s.id)}
					<tr>
						<td class="px-4 py-2.5 whitespace-nowrap">
							<a href={resolve('/(app)/scans/[id]', { id: s.id })} class="hover:underline"
								>{when(s.created_at)}</a
							>
						</td>
						<td class="px-4 py-2.5 font-mono text-xs">
							{s.targets.slice(0, 3).join(', ')}{s.targets.length > 3
								? ` +${s.targets.length - 3}`
								: ''}
						</td>
						<td class="px-4 py-2.5">{s.scope_group_name}</td>
						<td class="px-4 py-2.5"
							><ScanStateBadge state={s.state} cancelRequested={s.cancel_requested} /></td
						>
						<td class="px-4 py-2.5 text-slate-600">{s.requested_by_email ?? '—'}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if data.page.total > data.page.items.length}
		<p class="mt-2 text-xs text-slate-500">
			Showing the newest {data.page.items.length} of {data.page.total}.
		</p>
	{/if}
{/if}
