<script lang="ts">
	import type { RiskBand, Severity } from '#lib/types.js';

	// One badge for a severity rating or a risk band; colour follows the level, text names it.
	let { level, score }: { level: Severity | RiskBand; score?: number | null } = $props();

	const tone: Record<Severity | RiskBand, string> = {
		urgent: 'bg-red-700 text-white ring-red-700',
		critical: 'bg-red-50 text-red-800 ring-red-300',
		high: 'bg-orange-50 text-orange-800 ring-orange-300',
		medium: 'bg-amber-50 text-amber-900 ring-amber-300',
		low: 'bg-slate-50 text-slate-700 ring-slate-300',
		info: 'bg-white text-slate-600 ring-slate-200'
	};
</script>

<span
	class={[
		'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap capitalize ring-1',
		tone[level]
	]}
	>{level}{#if score != null}<span class="tabular-nums opacity-80">{score}</span>{/if}</span
>
