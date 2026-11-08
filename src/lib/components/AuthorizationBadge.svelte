<script lang="ts">
	import type { AuthorizationStatus } from '#lib/types.js';

	let { status }: { status: AuthorizationStatus } = $props();

	const label: Record<AuthorizationStatus, string> = {
		authorized: 'Authorized',
		changed_since_authorization: 'Changed since authorization',
		not_authorized: 'Not authorized'
	};
</script>

<span
	class={[
		'inline-block rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
		status === 'authorized' && 'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-200',
		status === 'changed_since_authorization' && 'bg-amber-50 text-amber-900 ring-1 ring-amber-200',
		status === 'not_authorized' && 'bg-slate-100 text-slate-700 ring-1 ring-slate-200'
	]}>{label[status]}</span
>
