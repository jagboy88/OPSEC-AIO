<script lang="ts">
  import { formatSafetyNumber } from '@opsec-aio/chat';
  import QrCode from '#lib/components/QrCode.svelte';
  import { chat } from './state.svelte.js';

  let { username, onClose }: { username: string; onClose: () => void } = $props();

  let digits = $state<string | null | undefined>(undefined);
  let verified = $state(false);

  $effect(() => {
    void chat.version;
    const c = chat.client;
    if (!c) return;
    void c.safetyNumber(username).then((d) => (digits = d));
    void c.identity(username).then((r) => (verified = !!r?.verified));
  });

  async function toggle() {
    await chat.client?.setVerified(username, !verified);
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
  {/if}
</section>
