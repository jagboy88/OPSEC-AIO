<script lang="ts">
  import { ChatInputError, type Conversation } from '@opsec-aio/chat';
  import { GROUP_MAX_MEMBERS } from '@opsec-aio/types';
  import { chat } from './state.svelte.js';

  let { conv, onClose }: { conv: Conversation; onClose: () => void } = $props();

  const me = $derived(chat.client?.username ?? '');
  const isAdmin = $derived(conv.admin === me);

  let adding = $state('');
  let busy = $state(false);
  let error = $state('');

  async function change(add: string[], remove: string[]) {
    error = '';
    busy = true;
    try {
      await chat.client!.updateGroupMembers(conv.id, add, remove);
      return true;
    } catch (err) {
      error =
        err instanceof ChatInputError
          ? err.message
          : 'Could not update the group. Check your connection and try again.';
      return false;
    } finally {
      busy = false;
    }
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    const names = adding.split(/[\s,]+/).filter(Boolean);
    if (!names.length) return;
    if (await change(names, [])) adding = '';
  }
</script>

<section
  class="space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-5"
  aria-labelledby="gm-title"
>
  <div class="flex items-center justify-between">
    <h3 id="gm-title" class="font-semibold text-neutral-100">
      Members ({conv.members.length}/{GROUP_MAX_MEMBERS})
    </h3>
    <button type="button" class="text-sm text-neutral-400 hover:text-neutral-100" onclick={onClose}
      >Close</button
    >
  </div>
  <p class="text-sm text-neutral-400">
    {#if isAdmin}
      You created this group, so only you can add or remove people. Everyone sees each change. New
      members only see messages sent after they join.
    {:else}
      Only the person who created this group{conv.admin ? ` (@${conv.admin})` : ''} can change its members.
    {/if}
  </p>
  <ul class="divide-y divide-neutral-800 text-sm" data-testid="group-members">
    {#each conv.members as m (m)}
      <li class="flex items-center justify-between gap-3 py-2">
        <span class="truncate text-neutral-100">
          @{m}
          {#if m === me}<span class="text-neutral-500">(you)</span>{/if}
          {#if m === conv.admin}<span class="text-neutral-500">· creator</span>{/if}
        </span>
        {#if isAdmin && m !== me}
          <button
            type="button"
            class="shrink-0 rounded px-2 py-1 text-xs text-red-400 hover:bg-neutral-800 disabled:opacity-40"
            disabled={busy || conv.members.length <= 2}
            onclick={() => change([], [m])}
            aria-label="Remove @{m}">Remove</button
          >
        {/if}
      </li>
    {/each}
  </ul>
  {#if isAdmin}
    <form class="flex gap-2" onsubmit={add}>
      <label class="sr-only" for="gm-add">Usernames to add</label>
      <input
        id="gm-add"
        bind:value={adding}
        placeholder="@username, @another"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        class="min-w-0 flex-1 rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-neutral-100"
      />
      <button
        type="submit"
        disabled={busy || !adding.trim() || conv.members.length >= GROUP_MAX_MEMBERS}
        class="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40"
        >Add</button
      >
    </form>
  {/if}
  {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
</section>
