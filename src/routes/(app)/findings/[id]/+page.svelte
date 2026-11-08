<script lang="ts">
	import { enhance } from '$app/forms';
	import { resolve } from '$app/paths';
	import ConfidenceBadge from '#lib/components/ConfidenceBadge.svelte';
	import Notice from '#lib/components/Notice.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import { STATUS_LABEL, can, type FindingStatus } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const f = $derived(data.finding);
	const triage = $derived(can(data.session, 'findings.triage'));
	const work = $derived(can(data.session, 'findings.work'));
	const accept = $derived(can(data.session, 'findings.accept'));
	const when = (iso: string | null) =>
		iso
			? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
			: '—';
	const pct = (v: number | null) => (v == null ? '—' : `${(v * 100).toFixed(1)}%`);

	// What each role may move a finding to; "resolved" is reserved for a verifying scan.
	const targets = $derived(
		(
			[
				['triaged', triage],
				['in_remediation', work],
				['fix_claimed', work],
				['false_positive', triage],
				['risk_accepted', accept],
				['closed_unverified', triage],
				['open', triage]
			] as [FindingStatus, boolean][]
		).filter(([s, ok]) => ok && s !== f.status)
	);
	let nextStatus = $state<FindingStatus | ''>('');
	const needsReason = $derived(
		nextStatus === 'false_positive' ||
			nextStatus === 'risk_accepted' ||
			nextStatus === 'closed_unverified'
	);
	const today = new Date().toISOString().slice(0, 10);
	const yearAhead = new Date(Date.now() + 365 * 86400_000).toISOString().slice(0, 10);

	const eventLabel: Record<string, string> = {
		detected: 'Detected by a scan',
		observed: 'Observed again by a scan',
		status_changed: 'Status changed',
		assigned: 'Assignment changed',
		comment: 'Comment',
		verification_passed: 'Verified fixed by a scan',
		verification_inconclusive: 'Verification inconclusive',
		reopened: 'Reopened: detected again',
		reassessed: 'Reassessed'
	};
	const describe = (d: Record<string, unknown>) =>
		Object.entries(d)
			.filter(([k]) => k !== 'text')
			.map(([k, v]) => `${k.replaceAll('_', ' ')}: ${Array.isArray(v) ? v.join(' → ') : String(v)}`)
			.join(' · ');
	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>{f.title} · Findings · VULNEX</title></svelte:head>

<p class="text-sm">
	<a href={resolve('/(app)/findings')} class="text-slate-600 hover:underline">Findings</a>
</p>
<h1 class="mt-1 text-xl font-semibold tracking-tight">{f.title}</h1>
<div class="mt-2 flex flex-wrap items-center gap-2 text-sm">
	<SeverityBadge level={f.risk_band} score={f.risk_score} />
	<SeverityBadge level={f.severity} />
	<ConfidenceBadge confidence={f.confidence} />
	<span class="rounded bg-white px-1.5 py-0.5 text-xs ring-1 ring-slate-300"
		>{STATUS_LABEL[f.status]}</span
	>
	{#if f.kev}
		<span class="rounded bg-red-700 px-1.5 py-0.5 text-xs font-semibold text-white"
			>CISA KEV: known exploited</span
		>
	{/if}
	{#if f.overdue}<span class="text-xs font-medium text-red-700">Overdue</span>{/if}
</div>

<Notice message={form?.message} success={form?.success} />

<dl
	class="mt-6 grid gap-x-8 gap-y-3 rounded-md border border-slate-200 bg-white p-4 text-sm sm:grid-cols-3"
>
	<div>
		<dt class="text-xs text-slate-500">Asset</dt>
		<dd>
			{#if can(data.session, 'assets.read')}
				<a
					href={resolve('/(app)/assets/[id]', { id: f.asset_id })}
					class="font-mono hover:underline">{f.asset_target}</a
				>
			{:else}
				<span class="font-mono">{f.asset_target}</span>
			{/if}
			{#if f.asset_name}<span class="text-slate-500"> · {f.asset_name}</span>{/if}
		</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Service</dt>
		<dd class="font-mono">
			{f.address ?? '—'}{f.port ? `:${f.port}` : ''}{f.service_name ? ` (${f.service_name})` : ''}
		</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Asset criticality</dt>
		<dd class="capitalize">{f.asset_criticality}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">First seen / last seen</dt>
		<dd>{when(f.first_seen_at)} / {when(f.last_seen_at)}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Assignee · due</dt>
		<dd>{f.assignee_email ?? 'Unassigned'} · {f.due_date ?? 'no due date'}</dd>
	</div>
	<div>
		<dt class="text-xs text-slate-500">Check</dt>
		<dd class="font-mono text-xs">{f.check_id} · {f.check_version}</dd>
	</div>
	{#if f.resolved_at}
		<div>
			<dt class="text-xs text-slate-500">Resolved</dt>
			<dd>
				{when(f.resolved_at)}
				{#if f.resolved_by_scan_id && can(data.session, 'scans.read')}
					· <a href={resolve('/(app)/scans/[id]', { id: f.resolved_by_scan_id })} class="underline"
						>verifying scan</a
					>
				{/if}
			</dd>
		</div>
	{/if}
	{#if f.accepted_until}
		<div>
			<dt class="text-xs text-slate-500">Risk accepted until</dt>
			<dd>{f.accepted_until}</dd>
		</div>
	{/if}
	{#if f.status_reason}
		<div class="sm:col-span-3">
			<dt class="text-xs text-slate-500">Reason for current status</dt>
			<dd>{f.status_reason}</dd>
		</div>
	{/if}
</dl>

{#if f.not_observed_since}
	<p class="mt-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
		Not observed since {when(f.not_observed_since)}: the latest scan could not run this check (port
		closed, filtered, or no data). That does not prove a fix, so the finding stays open.
	</p>
{/if}

<div class="mt-6 grid gap-6 lg:grid-cols-3">
	<div class="space-y-6 lg:col-span-2">
		<section aria-labelledby="why" class="rounded-md border border-slate-200 bg-white p-4">
			<h2 id="why" class="text-sm font-medium">Why this was reported</h2>
			<p class="mt-2 text-sm leading-relaxed whitespace-pre-line">{f.explanation}</p>
			{#if f.remediation}
				<h3 class="mt-4 text-xs font-medium text-slate-500 uppercase">Remediation</h3>
				<p class="mt-1 text-sm leading-relaxed">{f.remediation}</p>
			{/if}
		</section>

		{#if f.intel.length}
			<section aria-labelledby="intel" class="rounded-md border border-slate-200 bg-white">
				<h2 id="intel" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
					Vulnerability intelligence ({f.intel.length})
				</h2>
				<div class="overflow-x-auto">
					<table class="w-full text-left text-sm">
						<thead class="border-b border-slate-200 text-xs text-slate-500">
							<tr>
								<th scope="col" class="px-4 py-2 font-medium">CVE</th>
								<th scope="col" class="px-4 py-2 font-medium">CVSS</th>
								<th scope="col" class="px-4 py-2 font-medium">EPSS</th>
								<th scope="col" class="px-4 py-2 font-medium">KEV</th>
								<th scope="col" class="px-4 py-2 font-medium">Summary</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-slate-100 align-top">
							{#each f.intel as c (c.id)}
								<tr>
									<td class="px-4 py-2 font-mono text-xs whitespace-nowrap">
										<a href="{resolve('/(app)/intelligence')}?cve={c.id}" class="hover:underline"
											>{c.id}</a
										>
									</td>
									<td
										class="px-4 py-2 text-xs whitespace-nowrap tabular-nums"
										title={c.cvss_vector ?? ''}
									>
										{c.cvss_score ?? '—'}{c.cvss_version ? ` (v${c.cvss_version})` : ''}
									</td>
									<td
										class="px-4 py-2 text-xs tabular-nums"
										title="Percentile {pct(c.epss_percentile)}">{pct(c.epss)}</td
									>
									<td class="px-4 py-2 text-xs">
										{#if c.kev}<span class="font-semibold text-red-700">Yes</span>
											{#if c.kev_due}<div class="text-slate-500">due {c.kev_due}</div>{/if}
										{:else}—{/if}
									</td>
									<td class="max-w-md px-4 py-2 text-xs text-slate-700"
										>{c.description.slice(0, 280)}{c.description.length > 280 ? '…' : ''}</td
									>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<p class="border-t border-slate-100 px-4 py-2 text-xs text-slate-500">
					Source: NVD (CVSS, affected versions), CISA KEV, FIRST EPSS. This product uses data from
					the NVD API but is not endorsed or certified by the NVD.
				</p>
			</section>
		{/if}

		<section aria-labelledby="evidence" class="rounded-md border border-slate-200 bg-white">
			<h2 id="evidence" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
				Evidence
			</h2>
			{#each f.evidence as e (e.id)}
				<div class="border-b border-slate-100 px-4 py-3 last:border-b-0">
					<p class="text-xs text-slate-500">
						{e.kind} observation of <span class="font-mono">{e.address}:{e.port}</span> at {when(
							e.observed_at
						)} · scanner {e.scanner_version}
						{#if can(data.session, 'scans.read')}
							· <a href={resolve('/(app)/scans/[id]', { id: e.scan_id })} class="underline">scan</a>
						{/if}
					</p>
					<pre
						class="mt-2 max-h-80 overflow-auto rounded bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">{JSON.stringify(
							e.data,
							null,
							2
						)}</pre>
				</div>
			{:else}
				<p class="px-4 py-3 text-sm text-slate-500">No evidence is attached.</p>
			{/each}
		</section>
	</div>

	<div class="space-y-6">
		<section aria-labelledby="risk" class="rounded-md border border-slate-200 bg-white">
			<h2 id="risk" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">
				Priority {f.risk_score}/100
			</h2>
			<ul class="divide-y divide-slate-100 text-sm">
				{#each f.risk_factors.factors as factor (factor.factor)}
					<li class="flex justify-between gap-3 px-4 py-2">
						<span>
							<span class="capitalize">{factor.factor.replaceAll('_', ' ')}</span>
							<span class="block text-xs text-slate-500"
								>{factor.source}{factor.provisional ? ' · provisional' : ''}</span
							>
						</span>
						<span class="tabular-nums">+{factor.contribution}</span>
					</li>
				{/each}
			</ul>
			<p class="border-t border-slate-100 px-4 py-2 text-xs text-slate-500">
				Model {f.risk_factors.model}: 5 × severity + known exploited + exposure + criticality.
				Scores rank work; they are not probabilities. EPSS {pct(f.epss)} is shown, not scored.
			</p>
		</section>

		{#if targets.length}
			<section aria-labelledby="workflow" class="rounded-md border border-slate-200 bg-white p-4">
				<h2 id="workflow" class="text-sm font-medium">Workflow</h2>
				<form method="POST" action="?/status" use:enhance class="mt-3 space-y-3">
					<label class="block text-sm">
						<span class="text-xs text-slate-600">Move to</span>
						<select name="status" bind:value={nextStatus} required class={input}>
							<option value="" disabled>Choose…</option>
							{#each targets as [s] (s)}<option value={s}>{STATUS_LABEL[s]}</option>{/each}
						</select>
					</label>
					{#if needsReason}
						<label class="block text-sm">
							<span class="text-xs text-slate-600">Reason (required, recorded in the history)</span>
							<textarea name="reason" required maxlength="1000" rows="2" class={input}
								>{form?.action === 'status' ? (form.values?.reason ?? '') : ''}</textarea
							>
						</label>
					{/if}
					{#if nextStatus === 'risk_accepted'}
						<label class="block text-sm">
							<span class="text-xs text-slate-600">Accepted until (at most one year)</span>
							<input
								type="date"
								name="accepted_until"
								required
								min={today}
								max={yearAhead}
								class={input}
							/>
						</label>
					{/if}
					{#if nextStatus === 'fix_claimed'}
						<p class="text-xs text-slate-500">
							The next scan of this asset verifies the fix; only that can mark it resolved.
						</p>
					{/if}
					<button class="rounded bg-slate-900 px-3 py-1.5 text-sm font-medium text-white"
						>Update status</button
					>
				</form>
			</section>
		{/if}

		{#if triage}
			<section aria-labelledby="assign" class="rounded-md border border-slate-200 bg-white p-4">
				<h2 id="assign" class="text-sm font-medium">Assignment</h2>
				<form method="POST" action="?/assign" use:enhance class="mt-3 space-y-3">
					<label class="block text-sm">
						<span class="text-xs text-slate-600">Assignee</span>
						<select name="assignee_id" class={input}>
							<option value="">Unassigned</option>
							{#each data.members.filter((m) => m.is_active) as m (m.user_id)}
								<option value={m.user_id} selected={m.user_id === f.assignee_id}>{m.email}</option>
							{/each}
						</select>
					</label>
					<label class="block text-sm">
						<span class="text-xs text-slate-600">Due date</span>
						<input type="date" name="due_date" value={f.due_date ?? ''} class={input} />
					</label>
					<button
						class="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50"
						>Save</button
					>
				</form>
			</section>
		{/if}
	</div>
</div>

<section aria-labelledby="history" class="mt-6 rounded-md border border-slate-200 bg-white">
	<h2 id="history" class="border-b border-slate-200 px-4 py-2.5 text-sm font-medium">History</h2>
	{#if work}
		<form
			method="POST"
			action="?/comment"
			use:enhance
			class="flex gap-2 border-b border-slate-100 px-4 py-3"
		>
			<label class="sr-only" for="comment">Comment</label>
			<input
				id="comment"
				name="text"
				required
				maxlength="4000"
				placeholder="Add a comment"
				value={form?.action === 'comment' ? (form.values?.text ?? '') : ''}
				class="block w-full rounded border-slate-300 text-sm"
			/>
			<button class="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
				>Post</button
			>
		</form>
	{/if}
	<ol class="divide-y divide-slate-100 text-sm">
		{#each f.events as e (e.id)}
			<li class="px-4 py-2.5">
				<p>
					<span class="font-medium">{eventLabel[e.kind] ?? e.kind}</span>
					<span class="text-xs text-slate-500">
						· {when(e.at)} · {e.actor_email ?? 'VULNEX (automatic)'}</span
					>
				</p>
				{#if e.kind === 'comment'}
					<p class="mt-1 whitespace-pre-line">{String(e.detail.text ?? '')}</p>
				{:else if Object.keys(e.detail).length}
					<p class="mt-0.5 text-xs text-slate-600">{describe(e.detail)}</p>
				{/if}
			</li>
		{:else}
			<li class="px-4 py-3 text-slate-500">No history yet.</li>
		{/each}
	</ol>
</section>
