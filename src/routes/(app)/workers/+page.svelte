<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import Notice from '#lib/components/Notice.svelte';
	import { can, type Worker } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const manage = $derived(can(data.session, 'workers.manage'));
	const authorized = $derived(data.groups.filter((g) => g.authorization.status === 'authorized'));
	const created = $derived(
		form && 'bundle' in form && form.bundle && form.name && form.expires_at
			? { bundle: form.bundle, name: form.name, expires_at: form.expires_at }
			: null
	);
	const bundleHref = $derived(
		created ? `data:application/json;charset=utf-8,${encodeURIComponent(created.bundle)}` : ''
	);
	const groupName = (id: string) => data.groups.find((g) => g.id === id)?.name ?? '—';
	const when = (iso: string | null) =>
		iso
			? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
			: '—';
	const connection: Record<Worker['connection'], string> = {
		online: 'Online',
		stale: 'Not seen recently',
		never_connected: 'Never connected'
	};
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
	const confirmRevoke = (name: string) => (e: SubmitEvent) => {
		if (!confirm(`Revoke scanner "${name}"? It stops working at once and must be enrolled again.`))
			e.preventDefault();
	};
</script>

<svelte:head><title>Scanners · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Scanners</h1>
<p class="mt-1 max-w-3xl text-sm text-slate-600">
	Scanners run inside your network and connect out to VULNEX; nothing connects in to them. Each is
	enrolled for one scope group, verifies every signed scope it receives, and refuses targets outside
	it. Revoking a scanner disables its certificate immediately.
</p>

<Notice message={form?.message} success={form && 'success' in form ? form.success : null} />

{#if created}
	<section
		aria-labelledby="bundle"
		class="mt-6 rounded-md border border-amber-300 bg-amber-50 p-4 text-sm"
	>
		<h2 id="bundle" class="font-medium text-amber-950">
			Enrollment bundle for “{created.name}”
		</h2>
		<p class="mt-1 text-amber-950">
			Shown once. It contains a single-use token valid until {when(created.expires_at)}; treat it
			like a password. On the scanner host:
		</p>
		<pre
			class="mt-2 overflow-x-auto rounded bg-white p-2 font-mono text-xs ring-1 ring-amber-200">vulnex-scanner enroll --bundle vulnex-bundle.json
vulnex-scanner run</pre>
		<!-- eslint-disable svelte/no-navigation-without-resolve -- a data: download, not navigation -->
		<a
			href={bundleHref}
			download="vulnex-bundle.json"
			class="mt-3 inline-block rounded bg-slate-900 px-3 py-2 font-medium text-white hover:bg-slate-800"
			>Download vulnex-bundle.json</a
		>
		<!-- eslint-enable svelte/no-navigation-without-resolve -->
	</section>
{/if}

{#if data.loadError}
	<Notice message="Scanners could not be loaded: {data.loadError}" />
{:else if data.workers.length === 0}
	<p
		class="mt-6 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
	>
		No scanners enrolled.
		{manage
			? 'Create an enrollment bundle below and give it to the person installing the scanner.'
			: 'An owner or administrator enrolls scanners.'}
	</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium">Scanner</th>
					<th scope="col" class="px-4 py-2 font-medium">Scope group</th>
					<th scope="col" class="px-4 py-2 font-medium">Connection</th>
					<th scope="col" class="px-4 py-2 font-medium">Last seen</th>
					<th scope="col" class="px-4 py-2 font-medium">Version</th>
					{#if manage}<th scope="col" class="px-4 py-2"><span class="sr-only">Actions</span></th
						>{/if}
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.workers as w (w.id)}
					<tr class={w.status === 'revoked' ? 'text-slate-400' : ''}>
						<td class="px-4 py-2.5 font-medium">{w.name}</td>
						<td class="px-4 py-2.5">
							<a
								href={resolve('/(app)/scope/[id]', { id: w.scope_group_id })}
								class="hover:underline">{w.scope_group_name}</a
							>
						</td>
						<td class="px-4 py-2.5">
							{#if w.status === 'revoked'}
								Revoked {when(w.revoked_at)}
							{:else}
								<span
									class={[
										'inline-block rounded px-1.5 py-0.5 text-xs font-medium ring-1',
										w.connection === 'online'
											? 'bg-emerald-50 text-emerald-800 ring-emerald-200'
											: 'bg-slate-100 text-slate-700 ring-slate-200'
									]}>{connection[w.connection]}</span
								>
							{/if}
						</td>
						<td class="px-4 py-2.5 whitespace-nowrap">{when(w.last_seen_at)}</td>
						<td class="px-4 py-2.5 font-mono text-xs">{w.version ?? '—'}</td>
						{#if manage}
							<td class="px-4 py-2.5 text-right">
								{#if w.status !== 'revoked'}
									<form
										method="POST"
										action="?/revoke"
										use:enhance
										onsubmit={confirmRevoke(w.name)}
									>
										<input type="hidden" name="id" value={w.id} />
										<button class="text-sm text-red-700 hover:underline">Revoke</button>
									</form>
								{/if}
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if manage}
	<section aria-labelledby="enroll" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="enroll" class="text-sm font-medium">Enroll a scanner</h2>
		{#if authorized.length === 0}
			<p class="mt-2 text-sm text-slate-600">
				Authorize a <a href={resolve('/(app)/scope')} class="underline">scope group</a> first: a scanner
				is enrolled for one authorized scope group.
			</p>
		{:else}
			<form method="POST" action="?/enroll" use:enhance class="mt-4 grid gap-4 sm:grid-cols-3">
				<label class="block text-sm">
					<span class="font-medium">Scanner name</span>
					<input
						name="name"
						required
						maxlength="100"
						class={input}
						placeholder="hq-scanner-1"
						value={form?.values?.name ?? ''}
					/>
				</label>
				<label class="block text-sm">
					<span class="font-medium">Scope group</span>
					<select name="scope_group_id" required class={input}>
						{#each authorized as g (g.id)}
							<option value={g.id} selected={form?.values?.scope_group_id === g.id}>{g.name}</option
							>
						{/each}
					</select>
				</label>
				<label class="block text-sm">
					<span class="font-medium">Token valid for</span>
					<select name="ttl_hours" class={input}>
						<option value="1">1 hour</option>
						<option value="8">8 hours</option>
						<option value="24" selected>24 hours</option>
					</select>
				</label>
				<div class="sm:col-span-3">
					<button
						class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
						>Create enrollment bundle</button
					>
				</div>
			</form>
		{/if}

		{#if data.enrollments.length}
			<h3 class="mt-6 text-xs font-medium text-slate-500">Recent enrollment tokens</h3>
			<ul class="mt-2 divide-y divide-slate-100 text-sm">
				{#each data.enrollments as e (e.id)}
					<li class="flex flex-wrap items-center gap-x-4 gap-y-1 py-2">
						<span class="font-medium">{e.name}</span>
						<span class="text-slate-600">{groupName(e.scope_group_id)}</span>
						<span class="text-slate-500">
							{#if e.status === 'pending'}Unused, expires {when(e.expires_at)}
							{:else if e.status === 'used'}Used
							{:else if e.status === 'expired'}Expired
							{:else}Withdrawn{/if}
						</span>
						{#if e.status === 'pending'}
							<form method="POST" action="?/revokeEnrollment" use:enhance class="ml-auto">
								<input type="hidden" name="id" value={e.id} />
								<button class="text-sm text-red-700 hover:underline">Withdraw</button>
							</form>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</section>
{/if}
