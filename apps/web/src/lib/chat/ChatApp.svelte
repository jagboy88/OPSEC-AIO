<script lang="ts">
  import ConversationView from './ConversationView.svelte';
  import NewChat from './NewChat.svelte';
  import { chat } from './state.svelte.js';

  let selected = $state<string | null>(null);
  let showNew = $state(false);
  let showSettings = $state(false);
  let confirmDelete = $state('');
  let notice = $state('');

  const conversations = $derived(chat.conversations());

  async function exportKeys() {
    const blob = await chat.exportKeystore();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `opsec-aio-${chat.client?.username}.opsec`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
    notice =
      'Saved. The file is still protected by your passphrase. Use it on one device at a time: it moves the account, it does not copy it.';
  }

  async function deleteAccount() {
    await chat.deleteAccount();
  }
</script>

<div
  class="mt-4 grid h-[calc(100dvh-11rem)] min-h-[28rem] grid-cols-1 overflow-hidden rounded-xl border border-neutral-800 bg-neutral-900/40 md:grid-cols-[18rem_minmax(0,1fr)]"
>
  <aside
    class={[
      'flex min-h-0 flex-col border-neutral-800 md:border-r',
      selected ? 'hidden md:flex' : 'flex',
    ]}
    aria-label="Conversations"
  >
    <div class="flex items-center gap-2 border-b border-neutral-800 px-4 py-3">
      <span
        class={['size-2 rounded-full', chat.online ? 'bg-emerald-400' : 'bg-neutral-600']}
        title={chat.online ? 'Connected' : 'Connecting…'}
      ></span>
      <span class="min-w-0 flex-1 truncate text-sm font-medium text-neutral-100" data-testid="me"
        >@{chat.client?.username}</span
      >
      <button
        type="button"
        class="rounded-lg px-2 py-1 text-sm text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100"
        onclick={() => ((showSettings = !showSettings), (showNew = false))}
        aria-expanded={showSettings}>Settings</button
      >
      <button
        type="button"
        class="rounded-lg bg-emerald-500 px-2.5 py-1 text-sm font-semibold text-neutral-950 hover:bg-emerald-400"
        onclick={() => ((showNew = !showNew), (showSettings = false))}
        aria-expanded={showNew}>New</button
      >
    </div>

    {#if showNew}
      <div class="border-b border-neutral-800 p-3">
        <NewChat
          onOpen={(id) => ((selected = id), (showNew = false))}
          onClose={() => (showNew = false)}
        />
      </div>
    {/if}

    {#if showSettings}
      <div class="space-y-3 border-b border-neutral-800 p-4 text-sm">
        <button
          type="button"
          class="w-full rounded-lg bg-neutral-800 px-3 py-2 text-left hover:bg-neutral-700"
          onclick={() => chat.lock()}>Lock (forget keys from memory)</button
        >
        <button
          type="button"
          class="w-full rounded-lg bg-neutral-800 px-3 py-2 text-left hover:bg-neutral-700"
          onclick={exportKeys}>Move account: export keystore</button
        >
        {#if notice}<p class="text-xs text-neutral-400">{notice}</p>{/if}
        <details class="rounded-lg border border-red-500/30 p-3">
          <summary class="cursor-pointer text-red-400">Delete account</summary>
          <p class="mt-2 text-neutral-400">
            Deletes your account and keys from the server and wipes this device. Type your username
            to confirm.
          </p>
          <input
            bind:value={confirmDelete}
            aria-label="Type your username to confirm"
            class="mt-2 w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2"
          />
          <button
            type="button"
            class="mt-2 w-full rounded-lg bg-red-500 px-3 py-2 font-medium text-neutral-950 disabled:opacity-40"
            disabled={confirmDelete !== chat.client?.username}
            onclick={deleteAccount}>Delete everything</button
          >
        </details>
      </div>
    {/if}

    <ul class="min-h-0 flex-1 overflow-y-auto" data-testid="conversation-list">
      {#each conversations as c (c.id)}
        <li>
          <button
            type="button"
            class={[
              'flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-neutral-800/60',
              selected === c.id && 'bg-neutral-800',
            ]}
            onclick={() => (selected = c.id)}
          >
            <span class="min-w-0 flex-1">
              <span class="block truncate text-sm font-medium text-neutral-100"
                >{c.kind === 'direct' ? `@${c.title}` : `# ${c.title}`}</span
              >
              <span class="block truncate text-xs text-neutral-500"
                >{c.timer ? '⏱ disappearing' : 'end-to-end encrypted'}</span
              >
            </span>
            {#if c.unread}
              <span
                class="rounded-full bg-emerald-500 px-2 py-0.5 text-xs font-semibold text-neutral-950"
                >{c.unread}</span
              >
            {/if}
          </button>
        </li>
      {:else}
        <li class="p-6 text-center text-sm text-neutral-500">
          No conversations yet. Tap <strong>New</strong> and enter someone's username.
        </li>
      {/each}
    </ul>
  </aside>

  <main class={['min-h-0 min-w-0', selected ? 'block' : 'hidden md:block']}>
    {#if selected && chat.client?.conversation(selected)}
      {#key selected}
        <ConversationView convId={selected} onBack={() => (selected = null)} />
      {/key}
    {:else}
      <div class="flex h-full items-center justify-center p-8 text-center text-sm text-neutral-500">
        Select a conversation. Messages are encrypted on your device with the Signal Protocol; the
        server only relays ciphertext and deletes it on delivery.
      </div>
    {/if}
  </main>
</div>
