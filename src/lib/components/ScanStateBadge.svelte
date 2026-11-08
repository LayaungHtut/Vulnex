<script lang="ts">
	import type { ScanState } from '#lib/types.js';

	let { state, cancelRequested = false }: { state: ScanState; cancelRequested?: boolean } =
		$props();

	const label: Record<ScanState, string> = {
		queued: 'Queued',
		running: 'Running',
		completed: 'Completed',
		failed: 'Failed',
		cancelled: 'Cancelled'
	};
</script>

<span
	class={[
		'inline-block rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1',
		state === 'completed' && 'bg-emerald-50 text-emerald-800 ring-emerald-200',
		state === 'failed' && 'bg-red-50 text-red-800 ring-red-200',
		(state === 'queued' || state === 'running') && 'bg-sky-50 text-sky-900 ring-sky-200',
		state === 'cancelled' && 'bg-slate-100 text-slate-700 ring-slate-200'
	]}>{label[state]}{cancelRequested && state === 'running' ? ' · cancelling' : ''}</span
>
