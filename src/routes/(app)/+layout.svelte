<script lang="ts">
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { ROLE_LABEL, can, type Permission } from '#lib/types.js';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	// Only implemented sections appear; each is hidden when the role cannot use it.
	const nav: { href: string; label: string; permission?: Permission }[] = [
		{ href: resolve(''), label: 'Overview' },
		{ href: resolve('assets'), label: 'Assets', permission: 'assets.read' },
		{ href: resolve('scans'), label: 'Scans', permission: 'scans.read' },
		{ href: resolve('scope'), label: 'Authorized scope', permission: 'scope.read' },
		{ href: resolve('workers'), label: 'Scanners', permission: 'workers.read' },
		{ href: resolve('members'), label: 'Members', permission: 'members.read' },
		{ href: resolve('audit'), label: 'Audit log', permission: 'audit.read' }
	];
	const visible = $derived(nav.filter((n) => !n.permission || can(data.session, n.permission)));
	const current = (href: string) =>
		href === resolve('') ? page.url.pathname === href : page.url.pathname.startsWith(href);
</script>

<div class="flex min-h-dvh bg-slate-50 text-slate-900">
	<aside class="hidden w-56 shrink-0 flex-col border-r border-slate-200 bg-white md:flex">
		<div class="px-5 py-4 text-sm font-semibold tracking-[0.2em]">VULNEX</div>
		<nav aria-label="Main" class="flex-1 px-2">
			<ul class="space-y-0.5 text-sm">
				{#each visible as item (item.href)}
					<li>
						<!-- eslint-disable svelte/no-navigation-without-resolve -- href is built with resolve() in `nav` -->
						<a
							href={item.href}
							aria-current={current(item.href) ? 'page' : undefined}
							class={[
								'block rounded px-3 py-1.5',
								current(item.href)
									? 'bg-slate-100 font-medium text-slate-900'
									: 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
							]}>{item.label}</a
						>
						<!-- eslint-enable svelte/no-navigation-without-resolve -->
					</li>
				{/each}
			</ul>
			<p class="mt-6 px-3 text-xs leading-relaxed text-slate-400">
				Network scanning and findings arrive in later milestones (M5–M8).
			</p>
		</nav>
	</aside>

	<div class="flex min-w-0 flex-1 flex-col">
		<header
			class="flex items-center justify-between gap-4 border-b border-slate-200 bg-white px-4 py-2.5 md:px-6"
		>
			<div class="min-w-0">
				<p class="truncate text-sm font-medium">{data.session.organization.name}</p>
				<p class="text-xs text-slate-500">{ROLE_LABEL[data.session.role]}</p>
			</div>
			<div class="flex items-center gap-4 text-sm">
				<span class="hidden text-slate-600 sm:inline">{data.session.user.email}</span>
				<form method="POST" action="/logout">
					<button
						class="rounded border border-slate-300 px-2.5 py-1 text-slate-700 hover:bg-slate-50"
						>Sign out</button
					>
				</form>
			</div>
		</header>
		<nav
			aria-label="Main (mobile)"
			class="flex gap-1 border-b border-slate-200 bg-white px-2 md:hidden"
		>
			{#each visible as item (item.href)}
				<!-- eslint-disable svelte/no-navigation-without-resolve -- href is built with resolve() in `nav` -->
				<a
					href={item.href}
					aria-current={current(item.href) ? 'page' : undefined}
					class={[
						'px-3 py-2 text-sm',
						current(item.href) ? 'border-b-2 border-slate-900 font-medium' : 'text-slate-600'
					]}>{item.label}</a
				>
				<!-- eslint-enable svelte/no-navigation-without-resolve -->
			{/each}
		</nav>
		<main class="mx-auto w-full max-w-5xl flex-1 px-4 py-8 md:px-6">
			{@render children()}
		</main>
	</div>
</div>
