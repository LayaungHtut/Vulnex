<script lang="ts">
	import { enhance } from '$app/forms';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();
	let pending = $state(false);
</script>

<svelte:head><title>Sign in · VULNEX</title></svelte:head>

<main class="flex min-h-dvh items-center justify-center bg-slate-50 px-4">
	<div class="w-full max-w-sm">
		<p class="text-sm font-semibold tracking-[0.2em] text-slate-900">VULNEX</p>
		<h1 class="mt-6 text-xl font-semibold tracking-tight text-slate-900">Sign in</h1>
		<p class="mt-1 text-sm text-slate-600">Use the account your organization's owner created.</p>

		{#if form?.message || data.apiError}
			<p
				role="alert"
				class="mt-6 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
			>
				{form?.message ?? data.apiError}
			</p>
		{/if}

		<form
			method="POST"
			class="mt-6 space-y-4"
			use:enhance={() => {
				pending = true;
				return async ({ update }) => {
					await update({ reset: false });
					pending = false;
				};
			}}
		>
			<label class="block text-sm">
				<span class="font-medium text-slate-800">Email</span>
				<input
					name="email"
					type="email"
					autocomplete="username"
					required
					value={form?.email ?? ''}
					class="mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900"
				/>
			</label>
			<label class="block text-sm">
				<span class="font-medium text-slate-800">Password</span>
				<input
					name="password"
					type="password"
					autocomplete="current-password"
					required
					class="mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900"
				/>
			</label>
			<button
				disabled={pending}
				class="w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:opacity-60"
			>
				{pending ? 'Signing in…' : 'Sign in'}
			</button>
		</form>
		<p class="mt-6 text-xs text-slate-500">
			No self-registration: accounts are provisioned by an organization owner or administrator.
		</p>
	</div>
</main>
