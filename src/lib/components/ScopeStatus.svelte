<script lang="ts">
	import type { Asset } from '#lib/types.js';

	let { scope }: { scope: Asset['scope'] } = $props();
</script>

{#if scope.authorized}
	<span class="text-emerald-800">Eligible</span>
{:else if !scope.in_scope}
	<span class="text-red-800" title={scope.problem}>Out of scope</span>
{:else}
	<span class="text-amber-900" title="The scope group is not currently authorized"
		>Scope not authorized</span
	>
{/if}
