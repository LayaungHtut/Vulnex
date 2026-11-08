<script lang="ts">
	import { ROLE_LABEL } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const label = {
		ready: 'Operational',
		unavailable: 'Degraded',
		unreachable: 'Unreachable'
	} as const;
	const fmt = (iso: string) =>
		new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
</script>

<svelte:head><title>Overview · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Overview</h1>
<p class="mt-1 text-sm text-slate-600">
	Signed in as {data.session.user.display_name}. Asset inventory and scanning are not available yet;
	there is no security data to summarize.
</p>

<div class="mt-6 grid gap-4 md:grid-cols-2">
	<section aria-labelledby="org" class="rounded-md border border-slate-200 bg-white">
		<h2 id="org" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">Workspace</h2>
		<dl class="divide-y divide-slate-100 text-sm">
			<div class="flex justify-between gap-4 px-4 py-2.5">
				<dt class="text-slate-500">Organization</dt>
				<dd class="truncate">{data.session.organization.name}</dd>
			</div>
			<div class="flex justify-between gap-4 px-4 py-2.5">
				<dt class="text-slate-500">Your role</dt>
				<dd>{ROLE_LABEL[data.session.role]}</dd>
			</div>
			<div class="flex justify-between gap-4 px-4 py-2.5">
				<dt class="text-slate-500">Session expires</dt>
				<dd><time datetime={data.session.expires_at}>{fmt(data.session.expires_at)}</time></dd>
			</div>
		</dl>
	</section>

	<section aria-labelledby="status" class="rounded-md border border-slate-200 bg-white">
		<h2 id="status" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
			System status
		</h2>
		<dl class="text-sm">
			<div class="flex items-center justify-between px-4 py-2.5">
				<dt class="text-slate-500">Control plane API</dt>
				<dd class="flex items-center gap-2" data-state={data.api.state}>
					<span
						aria-hidden="true"
						class={[
							'size-2 rounded-full',
							data.api.state === 'ready' ? 'bg-emerald-600' : 'bg-red-600'
						]}
					></span>
					{label[data.api.state]}
					{#if data.api.state === 'ready'}
						<span class="text-slate-500">v{data.api.version}</span>
					{:else if data.api.state === 'unavailable'}
						<span class="text-slate-500">{data.api.detail}</span>
					{/if}
				</dd>
			</div>
		</dl>
		<p class="border-t border-slate-100 px-4 py-2 text-xs text-slate-500">
			Checked <time datetime={data.checkedAt}>{fmt(data.checkedAt)}</time> · reload to re-check
		</p>
	</section>
</div>
