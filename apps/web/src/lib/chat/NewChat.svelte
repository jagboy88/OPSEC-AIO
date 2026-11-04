<script lang="ts">
  import { ChatInputError } from '@opsec-aio/chat';
  import { GROUP_MAX_MEMBERS } from '@opsec-aio/types';
  import { chat } from './state.svelte.js';

  let { onOpen, onClose }: { onOpen: (convId: string) => void; onClose: () => void } = $props();

  let mode = $state<'direct' | 'group'>('direct');
  let username = $state('');
  let groupName = $state('');
  let members = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const c = chat.client;
    if (!c) return;
    busy = true;
    error = '';
    try {
      const conv =
        mode === 'direct'
          ? await c.startDirect(username)
          : await c.createGroup(groupName, members.split(/[\s,]+/).filter(Boolean));
      onOpen(conv.id);
    } catch (err) {
      error =
        err instanceof ChatInputError ? err.message : 'Something went wrong. Please try again.';
    } finally {
      busy = false;
    }
  }

  const input =
    'w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-neutral-100';
</script>

<form class="space-y-3 rounded-xl border border-neutral-800 bg-neutral-900 p-4" onsubmit={submit}>
  <div class="flex gap-1 rounded-lg bg-neutral-950 p-1 text-sm" role="tablist">
    {#each [['direct', 'Person'], ['group', 'Group']] as [m, label] (m)}
      <button
        type="button"
        role="tab"
        aria-selected={mode === m}
        class={[
          'flex-1 rounded-md px-3 py-1.5',
          mode === m ? 'bg-neutral-800 text-neutral-50' : 'text-neutral-400',
        ]}
        onclick={() => (mode = m as 'direct' | 'group')}>{label}</button
      >
    {/each}
  </div>
  {#if mode === 'direct'}
    <input
      bind:value={username}
      placeholder="Their username"
      aria-label="Username"
      autocapitalize="none"
      autocomplete="off"
      spellcheck="false"
      class={input}
      required
    />
  {:else}
    <input
      bind:value={groupName}
      placeholder="Group name"
      aria-label="Group name"
      class={input}
      required
    />
    <input
      bind:value={members}
      placeholder="Members: alice, bob…"
      aria-label="Members"
      autocapitalize="none"
      autocomplete="off"
      spellcheck="false"
      class={input}
      required
    />
    <p class="text-xs text-neutral-500">
      Up to {GROUP_MAX_MEMBERS} people including you. Each message is encrypted separately for every member.
    </p>
  {/if}
  <div class="flex gap-2">
    <button
      type="submit"
      disabled={busy}
      class="flex-1 rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40"
      >{mode === 'direct' ? 'Start chat' : 'Create group'}</button
    >
    <button type="button" class="rounded-lg bg-neutral-800 px-3 py-2 text-sm" onclick={onClose}
      >Cancel</button
    >
  </div>
  {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
</form>
