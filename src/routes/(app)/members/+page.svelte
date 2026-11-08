<script lang="ts">
	import { enhance } from '$app/forms';
	import { ROLES, ROLE_LABEL, can, type Member } from '#lib/types.js';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	const manage = $derived(can(data.session, 'members.manage'));
	const isOwner = $derived(data.session.role === 'owner');
	// Mirrors the API rule (admins cannot grant or alter owner access); the API still decides.
	const assignable = $derived(isOwner ? ROLES : ROLES.filter((r) => r !== 'owner'));
	const editable = (m: Member) =>
		manage && (isOwner || m.role !== 'owner') && m.user_id !== data.session.user.id;
	const date = (iso: string) =>
		new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

	const input =
		'mt-1 block w-full rounded border-slate-300 text-sm shadow-xs focus:border-slate-900 focus:ring-slate-900';
</script>

<svelte:head><title>Members · VULNEX</title></svelte:head>

<h1 class="text-xl font-semibold tracking-tight">Members</h1>
<p class="mt-1 text-sm text-slate-600">
	People with access to {data.session.organization.name}. Roles follow PRD §10; changes take effect
	on the member's next request.
</p>

{#if form?.message || form?.success}
	<p
		role={form?.message ? 'alert' : 'status'}
		class={[
			'mt-4 rounded border px-3 py-2 text-sm',
			form?.message
				? 'border-red-200 bg-red-50 text-red-800'
				: 'border-emerald-200 bg-emerald-50 text-emerald-800'
		]}
	>
		{form?.message ?? form?.success}
	</p>
{/if}

{#if data.loadError}
	<p
		role="alert"
		class="mt-6 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
	>
		Members could not be loaded: {data.loadError}
	</p>
{:else if data.members.length === 0}
	<p class="mt-6 text-sm text-slate-600">No members found.</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-slate-200 text-xs text-slate-500">
				<tr>
					<th scope="col" class="px-4 py-2 font-medium">Member</th>
					<th scope="col" class="px-4 py-2 font-medium">Role</th>
					<th scope="col" class="px-4 py-2 font-medium">Joined</th>
					{#if manage}<th scope="col" class="px-4 py-2"><span class="sr-only">Actions</span></th
						>{/if}
				</tr>
			</thead>
			<tbody class="divide-y divide-slate-100">
				{#each data.members as m (m.user_id)}
					<tr>
						<td class="px-4 py-2.5">
							<div class="font-medium">{m.display_name}</div>
							<div class="text-xs text-slate-500">
								{m.email}{#if !m.is_active}<span class="ml-2 text-red-700">· deactivated</span>{/if}
								{#if m.user_id === data.session.user.id}<span class="ml-2">· you</span>{/if}
							</div>
						</td>
						<td class="px-4 py-2.5">
							{#if editable(m)}
								<form method="POST" action="?/role" use:enhance class="flex items-center gap-2">
									<input type="hidden" name="user_id" value={m.user_id} />
									<label class="sr-only" for="role-{m.user_id}">Role for {m.email}</label>
									<select
										id="role-{m.user_id}"
										name="role"
										class="rounded border-slate-300 py-1 text-sm"
										value={m.role}
									>
										{#each assignable as r (r)}<option value={r}>{ROLE_LABEL[r]}</option>{/each}
									</select>
									<button
										class="rounded border border-slate-300 px-2 py-1 text-xs hover:bg-slate-50"
										>Save</button
									>
								</form>
							{:else}
								{ROLE_LABEL[m.role]}
							{/if}
						</td>
						<td class="px-4 py-2.5 text-slate-600">{date(m.joined_at)}</td>
						{#if manage}
							<td class="px-4 py-2.5 text-right">
								{#if editable(m)}
									<form
										method="POST"
										action="?/remove"
										use:enhance={({ cancel }) => {
											if (!confirm(`Remove ${m.email} from ${data.session.organization.name}?`))
												cancel();
										}}
									>
										<input type="hidden" name="user_id" value={m.user_id} />
										<button class="text-xs text-red-700 hover:underline">Remove</button>
									</form>
								{/if}
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if manage}
	<section aria-labelledby="add" class="mt-8 rounded-md border border-slate-200 bg-white p-4">
		<h2 id="add" class="text-sm font-medium">Add a member</h2>
		<p class="mt-1 text-xs text-slate-500">
			Creates an account with this initial password and shares it with the person out of band. If
			the email already has a VULNEX account, that account keeps its own password.
		</p>
		<form method="POST" action="?/add" use:enhance class="mt-4 grid gap-4 sm:grid-cols-2">
			<label class="block text-sm">
				<span class="font-medium">Email</span>
				<input name="email" type="email" required class={input} value={form?.values?.email ?? ''} />
			</label>
			<label class="block text-sm">
				<span class="font-medium">Name</span>
				<input
					name="display_name"
					required
					maxlength="100"
					class={input}
					value={form?.values?.display_name ?? ''}
				/>
			</label>
			<label class="block text-sm">
				<span class="font-medium">Role</span>
				<select name="role" class={input} value={form?.values?.role ?? 'viewer'}>
					{#each assignable as r (r)}<option value={r}>{ROLE_LABEL[r]}</option>{/each}
				</select>
			</label>
			<label class="block text-sm">
				<span class="font-medium">Initial password</span>
				<input
					name="password"
					type="password"
					autocomplete="new-password"
					required
					minlength="12"
					maxlength="128"
					class={input}
				/>
				<span class="mt-1 block text-xs text-slate-500">12–128 characters.</span>
			</label>
			<div class="sm:col-span-2">
				<button
					class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
					>Add member</button
				>
			</div>
		</form>
	</section>
{/if}
