<script lang="ts">
	import { CONFIDENCE_LABEL, type Confidence } from '#lib/types.js';

	let { confidence }: { confidence: Confidence } = $props();

	// PRD Amendment A1: only "confirmed" means the condition itself was observed.
	const hint: Record<Confidence, string> = {
		confirmed: 'The condition itself was observed',
		probable: 'Strong evidence, not directly observed',
		potential: 'Version correlation only; may be fixed by a backport',
		unknown: 'Not enough evidence to decide'
	};
</script>

<span
	title={hint[confidence]}
	class={[
		'inline-block rounded px-1.5 py-0.5 text-xs whitespace-nowrap ring-1',
		confidence === 'confirmed' && 'bg-slate-900 text-white ring-slate-900',
		confidence === 'probable' && 'bg-white text-slate-900 ring-slate-500',
		confidence === 'potential' && 'border-dashed bg-white text-slate-600 ring-slate-300',
		confidence === 'unknown' && 'bg-slate-50 text-slate-500 ring-slate-200'
	]}>{CONFIDENCE_LABEL[confidence]}</span
>
