<script lang="ts">
  import { ChatInputError, formatSafetyNumber } from '@opsec-aio/chat';
  import QrCode from '#lib/components/QrCode.svelte';
  import { chat } from './state.svelte.js';

  let { username, onClose }: { username: string; onClose: () => void } = $props();

  let digits = $state<string | null | undefined>(undefined);
  let verified = $state(false);
  /** Their key changed after the user verified it; the new key isn't accepted yet. */
  let pendingChange = $state(false);
  let error = $state('');

  async function load() {
    const c = chat.client;
    if (!c) return;
    const [d, r] = await Promise.all([c.safetyNumber(username), c.identity(username)]);
    digits = d;
    verified = !!r?.verified;
    pendingChange = !!(r?.verified && r.changed);
  }

  $effect(() => {
    void chat.version;
    void load();
  });

  async function toggle() {
    error = '';
    try {
      // Pass the number on screen: if the key changed meanwhile, nothing is marked.
      await chat.client?.setVerified(username, !verified, digits ?? undefined);
    } catch (err) {
      error = err instanceof ChatInputError ? err.message : 'Could not save. Try again.';
    }
    await load();
  }
</script>

<section
  class="space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-5"
  aria-labelledby="sn-title"
>
  <div class="flex items-center justify-between">
    <h3 id="sn-title" class="font-semibold text-neutral-100">Safety number with @{username}</h3>
    <button type="button" class="text-sm text-neutral-400 hover:text-neutral-100" onclick={onClose}
      >Close</button
    >
  </div>
  {#if digits === undefined}
    <p class="text-sm text-neutral-400">Computing…</p>
  {:else if pendingChange}
    <p class="text-sm text-amber-200" role="alert">
      @{username}'s key changed after you verified it. Accept the new key (the red banner above) to
      see the new safety number, then compare it again.
    </p>
  {:else if digits === null}
    <p class="text-sm text-neutral-400">
      Exchange a message first; the safety number comes from both of your keys.
    </p>
  {:else}
    <p class="text-sm text-neutral-400">
      Compare these numbers with @{username} in person or over a call, or scan each other's code. If they
      match, nobody is intercepting your messages.
    </p>
    <div
      class="grid grid-cols-4 gap-x-4 gap-y-1 font-mono text-lg tracking-wider text-neutral-100"
      data-testid="safety-number"
    >
      {#each formatSafetyNumber(digits).split(' ') as group, i (i)}
        <span>{group}</span>
      {/each}
    </div>
    <div class="max-w-48"><QrCode value={digits} label="Safety number QR code" /></div>
    <button
      type="button"
      onclick={toggle}
      class={[
        'rounded-lg px-4 py-2 text-sm font-medium',
        verified
          ? 'bg-neutral-800 text-neutral-200 hover:bg-neutral-700'
          : 'bg-emerald-500 text-neutral-950 hover:bg-emerald-400',
      ]}
    >
      {verified ? '✓ Verified (tap to clear)' : 'Mark as verified'}
    </button>
    {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
  {/if}
</section>
