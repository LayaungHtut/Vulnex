<script lang="ts">
	// Result of a form action, or a load error: an alert for failures, a status for success.
	let { message, success }: { message?: string | null; success?: string | null } = $props();
</script>

{#if message || success}
	<p
		role={message ? 'alert' : 'status'}
		class={[
			'mt-4 rounded border px-3 py-2 text-sm',
			message
				? 'border-red-200 bg-red-50 text-red-800'
				: 'border-emerald-200 bg-emerald-50 text-emerald-800'
		]}
	>
		{message ?? success}
	</p>
{/if}
