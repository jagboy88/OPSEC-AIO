<script lang="ts">
  import ChatApp from '#lib/chat/ChatApp.svelte';
  import ChatSetup from '#lib/chat/ChatSetup.svelte';
  import { chat } from '#lib/chat/state.svelte.js';

  let failed = $state(false);

  $effect(() => {
    chat.init().catch(() => (failed = true));
  });
</script>

<svelte:head><title>Chat · OpSec AIO</title></svelte:head>

<div class="flex items-baseline justify-between">
  <h1 class="mt-6 text-2xl font-semibold text-neutral-50">Chat</h1>
  {#if chat.phase === 'ready'}
    <p class="text-xs text-neutral-500">Signal Protocol · end-to-end encrypted</p>
  {/if}
</div>

{#if failed}
  <p class="mt-6 text-red-400" role="alert">
    This browser blocks local storage (private mode?), which chat needs to keep your keys.
  </p>
{:else if chat.phase === 'loading'}
  <p class="mt-6 text-neutral-400">Loading…</p>
{:else if chat.phase === 'ready'}
  <ChatApp />
{:else}
  <ChatSetup />
{/if}
