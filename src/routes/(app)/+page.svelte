<script lang="ts">
	import { resolve } from '$app/paths';
	import ScanStateBadge from '#lib/components/ScanStateBadge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import { ROLE_LABEL, type Severity } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const label = {
		ready: 'Operational',
		unavailable: 'Degraded',
		unreachable: 'Unreachable'
	} as const;
	const fmt = (iso: string) =>
		new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
	const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
	const bar: Record<Severity, string> = {
		critical: 'bg-red-600',
		high: 'bg-orange-500',
		medium: 'bg-amber-400',
		low: 'bg-slate-400',
		info: 'bg-slate-200'
	};
	const s = $derived(data.summary);
	const urgentHigh = $derived(s ? (s.by_band.urgent ?? 0) + (s.by_band.high ?? 0) : 0);
	const maxSeverity = $derived(
		s ? Math.max(1, ...severities.map((k) => s.by_severity[k] ?? 0)) : 1
	);
	const maxDay = $derived(
		s ? Math.max(1, ...s.trend_30d.map((d) => Math.max(d.opened, d.resolved))) : 1
	);
	const staleIntel = $derived(data.intel?.filter((x) => x.stale) ?? []);
</script>

<svelte:head><title>Overview · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Overview</h1>
<p class="mt-1 text-sm text-slate-600">
	{data.session.organization.name} · signed in as {data.session.user.display_name} ({ROLE_LABEL[
		data.session.role
	]}). Every number below is computed from stored scan results.
</p>

{#if staleIntel.length}
	<p class="mt-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
		Vulnerability intelligence is stale or missing ({staleIntel
			.map((x) => x.name.toUpperCase())
			.join(', ')}). CVE correlation and KEV status may be out of date.
		<a href={resolve('/(app)/intelligence')} class="underline">Details</a>
	</p>
{/if}

{#if s}
	<div class="mt-6 grid grid-cols-2 gap-3 md:grid-cols-5">
		{#each [{ k: 'Active findings', v: s.active, href: '?status=active' }, { k: 'Urgent or high priority', v: urgentHigh, href: '?band=urgent&band=high' }, { k: 'Known exploited (KEV)', v: s.kev, href: '?kev=true' }, { k: 'Overdue', v: s.overdue, href: '?sort=due' }, { k: 'Assets', v: data.assetTotal, href: null }] as tile (tile.k)}
			<div class="rounded-md border border-slate-200 bg-white px-4 py-3">
				<p class="text-xs text-slate-500">{tile.k}</p>
				<p class="mt-1 text-2xl font-semibold tabular-nums">
					{#if tile.href && tile.v}
						<a href="{resolve('/(app)/findings')}{tile.href}" class="hover:underline">{tile.v}</a>
					{:else}
						{tile.v ?? '—'}
					{/if}
				</p>
			</div>
		{/each}
	</div>

	{#if s.active === 0 && s.opened_30d === 0}
		<p
			class="mt-6 rounded-md border border-dashed border-slate-300 bg-white px-4 py-6 text-sm text-slate-600"
		>
			No findings yet. Register an asset in an authorized scope group, enroll a scanner, and run a
			<em>discovery</em> scan from the asset's page.
		</p>
	{:else}
		<div class="mt-4 grid gap-4 lg:grid-cols-3">
			<section aria-labelledby="sev" class="rounded-md border border-slate-200 bg-white p-4">
				<h2 id="sev" class="text-sm font-medium">Active findings by severity</h2>
				<ul class="mt-3 space-y-2 text-sm">
					{#each severities as k (k)}
						<li class="grid grid-cols-[5rem_1fr_2.5rem] items-center gap-2">
							<span class="text-xs text-slate-600 capitalize">{k}</span>
							<span class="h-2 rounded-r bg-slate-100">
								<span
									class={['block h-2 rounded-r', bar[k]]}
									style="width: {((s.by_severity[k] ?? 0) / maxSeverity) * 100}%"
								></span>
							</span>
							<span class="text-right text-xs tabular-nums">{s.by_severity[k] ?? 0}</span>
						</li>
					{/each}
				</ul>
				<p class="mt-4 text-xs text-slate-500">
					Confidence: {s.by_confidence.confirmed ?? 0} confirmed · {s.by_confidence.probable ?? 0} probable
					· {s.by_confidence.potential ?? 0} potential (version match only)
				</p>
			</section>

			<section
				aria-labelledby="trend"
				class="rounded-md border border-slate-200 bg-white p-4 lg:col-span-2"
			>
				<div class="flex flex-wrap items-baseline justify-between gap-2">
					<h2 id="trend" class="text-sm font-medium">Last 30 days</h2>
					<p class="flex gap-4 text-xs text-slate-600">
						<span class="flex items-center gap-1.5"
							><span class="size-2 rounded-sm bg-slate-700" aria-hidden="true"></span>Opened {s.opened_30d}</span
						>
						<span class="flex items-center gap-1.5"
							><span class="size-2 rounded-sm bg-emerald-500" aria-hidden="true"></span>Verified
							resolved
							{s.resolved_30d}</span
						>
					</p>
				</div>
				<div
					class="mt-4 flex h-28 items-end gap-0.5"
					role="img"
					aria-label="Findings opened and resolved per day over the last 30 days"
				>
					{#each s.trend_30d as d (d.day)}
						<div
							class="group relative flex h-full flex-1 items-end gap-px"
							title="{d.day}: {d.opened} opened, {d.resolved} resolved"
						>
							<span
								class="block w-1/2 rounded-t-sm bg-slate-700"
								style="height: {(d.opened / maxDay) * 100}%"
							></span>
							<span
								class="block w-1/2 rounded-t-sm bg-emerald-500"
								style="height: {(d.resolved / maxDay) * 100}%"
							></span>
						</div>
					{/each}
				</div>
				<div
					class="mt-1 flex justify-between border-t border-slate-200 pt-1 text-[11px] text-slate-500"
				>
					<span>{s.trend_30d[0]?.day}</span><span>{s.trend_30d.at(-1)?.day}</span>
				</div>
				<p class="mt-3 text-xs text-slate-500">
					Mean age of active findings {s.mean_age_days} days · {s.unassigned} unassigned · {s.not_observed}
					not observed in the latest scan · risk model {s.risk_model}
				</p>
			</section>
		</div>

		{#if s.top_assets.length}
			<section aria-labelledby="top" class="mt-4 rounded-md border border-slate-200 bg-white">
				<h2 id="top" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
					Assets needing attention
				</h2>
				<table class="w-full text-left text-sm">
					<thead class="text-xs text-slate-500">
						<tr>
							<th scope="col" class="px-4 py-2 font-medium">Asset</th>
							<th scope="col" class="px-4 py-2 font-medium">Criticality</th>
							<th scope="col" class="px-4 py-2 text-right font-medium">Active findings</th>
							<th scope="col" class="px-4 py-2 text-right font-medium">Highest priority</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-slate-100">
						{#each s.top_assets as a (a.id)}
							<tr>
								<td class="px-4 py-2">
									<a
										href="{resolve('/(app)/findings')}?asset_id={a.id}"
										class="font-mono text-xs hover:underline">{a.target}</a
									>
									{#if a.name}<span class="text-xs text-slate-500"> · {a.name}</span>{/if}
								</td>
								<td class="px-4 py-2 text-xs capitalize">{a.criticality}</td>
								<td class="px-4 py-2 text-right tabular-nums">{a.findings}</td>
								<td class="px-4 py-2 text-right">
									<SeverityBadge
										level={a.max_risk >= 80
											? 'urgent'
											: a.max_risk >= 60
												? 'high'
												: a.max_risk >= 35
													? 'medium'
													: 'low'}
										score={a.max_risk}
									/>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</section>
		{/if}
	{/if}
{/if}

<div class="mt-6 grid gap-4 md:grid-cols-2">
	{#if data.scans}
		<section aria-labelledby="scans" class="rounded-md border border-slate-200 bg-white">
			<h2 id="scans" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
				Recent scans
			</h2>
			<ul class="divide-y divide-slate-100 text-sm">
				{#each data.scans.items as scan (scan.id)}
					<li class="flex items-center justify-between gap-3 px-4 py-2">
						<a
							href={resolve('/(app)/scans/[id]', { id: scan.id })}
							class="min-w-0 truncate hover:underline"
						>
							{scan.profile === 'discovery' ? 'Discovery' : 'Scope check'} ·
							<span class="font-mono text-xs">{scan.targets.join(', ')}</span>
						</a>
						<ScanStateBadge state={scan.state} cancelRequested={scan.cancel_requested} />
					</li>
				{:else}
					<li class="px-4 py-3 text-slate-500">No scans yet.</li>
				{/each}
			</ul>
		</section>
	{/if}

	<section aria-labelledby="status" class="rounded-md border border-slate-200 bg-white">
		<h2 id="status" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
			System status
		</h2>
		<dl class="divide-y divide-slate-100 text-sm">
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
			{#each data.intel ?? [] as src (src.name)}
				<div class="flex items-center justify-between px-4 py-2.5">
					<dt class="text-slate-500">Intelligence: {src.name.toUpperCase()}</dt>
					<dd class="text-xs">
						{src.status === 'never'
							? 'Never synced'
							: src.stale
								? 'Stale'
								: src.status === 'error'
									? 'Last sync failed'
									: 'Current'}
						{#if src.last_success_at}<span class="text-slate-500">
								· {fmt(src.last_success_at)}</span
							>{/if}
					</dd>
				</div>
			{/each}
		</dl>
		<p class="border-t border-slate-100 px-4 py-2 text-xs text-slate-500">
			Checked <time datetime={data.checkedAt}>{fmt(data.checkedAt)}</time> · session expires
			<time datetime={data.session.expires_at}>{fmt(data.session.expires_at)}</time>
		</p>
	</section>
</div>
