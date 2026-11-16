<script lang="ts">
  import { CryptoUnavailableError, webAssemblyAvailable } from '@opsec-aio/crypto';
  import ChatApp from '#lib/chat/ChatApp.svelte';
  import ChatSetup from '#lib/chat/ChatSetup.svelte';
  import { chat } from '#lib/chat/state.svelte.js';
  import WasmNotice from '#lib/components/WasmNotice.svelte';

  let failure = $state<null | { kind: 'crypto' | 'storage'; detail: string }>(null);

  $effect(() => {
    chat.init().catch((e: unknown) => {
      const detail = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      failure = {
        kind: e instanceof CryptoUnavailableError || !webAssemblyAvailable() ? 'crypto' : 'storage',
        detail,
      };
    });
  });
</script>

<svelte:head><title>Chat · OpSec AIO</title></svelte:head>

<div class="flex items-baseline justify-between">
  <h1 class="mt-6 text-2xl font-semibold text-neutral-50">Chat</h1>
  {#if chat.phase === 'ready'}
    <p class="text-xs text-neutral-500">Signal Protocol · end-to-end encrypted</p>
  {/if}
</div>

{#if failure?.kind === 'crypto'}
  <div class="mt-6"><WasmNotice /></div>
{:else if failure?.kind === 'storage'}
  <div class="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm" role="alert">
    <p class="font-medium text-red-300">Chat couldn't open its encrypted storage on this device.</p>
    <p class="mt-1 text-neutral-300">
      Chat keeps your keys in the browser's site storage (IndexedDB). It may be blocked by a "block
      all cookies / site data" setting, a private-only browser (Firefox Focus, DuckDuckGo with
      Fire), or low storage space.
    </p>
    <p class="mt-2 font-mono text-xs text-neutral-500">{failure.detail}</p>
  </div>
{:else if chat.phase === 'loading'}
  <p class="mt-6 text-neutral-400">Loading…</p>
{:else if chat.phase === 'ready'}
  <ChatApp />
{:else}
  <ChatSetup />
{/if}
