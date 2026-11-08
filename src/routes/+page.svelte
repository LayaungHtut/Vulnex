<script lang="ts">
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const label = {
		ready: 'Operational',
		unavailable: 'Degraded',
		unreachable: 'Unreachable'
	} as const;
</script>

<svelte:head><title>VULNEX · System status</title></svelte:head>

<main class="mx-auto max-w-3xl px-6 py-12 text-slate-900">
	<h1 class="text-2xl font-semibold tracking-tight">VULNEX console</h1>
	<p class="mt-1 text-sm text-slate-600">
		Development foundation (M1). Sign-in, assets and scanning are not implemented yet.
	</p>

	<section aria-labelledby="status" class="mt-8 rounded-md border border-slate-200">
		<h2 id="status" class="border-b border-slate-200 px-4 py-3 text-sm font-medium">
			System status
		</h2>
		<dl class="divide-y divide-slate-200 text-sm">
			<div class="flex items-center justify-between px-4 py-3">
				<dt>Control plane API</dt>
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
		<p class="border-t border-slate-200 px-4 py-2 text-xs text-slate-500">
			Checked <time datetime={data.checkedAt}>{data.checkedAt}</time> · reload to re-check
		</p>
	</section>
</main>
