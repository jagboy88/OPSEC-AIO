<script lang="ts">
  import {
    ChatInputError,
    IdentityChangedError,
    timerLabel,
    type IdentityRecord,
    type StoredMessage,
  } from '@opsec-aio/chat';
  import { DISAPPEARING_TIMER_OPTIONS_SECONDS } from '@opsec-aio/types';
  import { downloadAttachment, uploadAttachment } from '#lib/drop.js';
  import { formatBytes, formatRemaining } from '#lib/format.js';
  import SafetyNumber from './SafetyNumber.svelte';
  import { chat } from './state.svelte.js';

  let { convId, onBack }: { convId: string; onBack: () => void } = $props();

  const conv = $derived((void chat.version, chat.client?.conversation(convId)));
  const messages = $derived(chat.messages(convId));
  const me = $derived(chat.client?.username ?? '');

  let draft = $state('');
  let sending = $state(false);
  let error = $state('');
  let blockedBy = $state<string | null>(null);
  let showSafety = $state(false);
  let showMenu = $state(false);
  let uploading = $state<number | null>(null);
  let downloading = $state<Record<string, number>>({});
  let identity = $state<IdentityRecord | undefined>(undefined);
  let now = $state(Date.now());
  let list: HTMLElement | undefined = $state();

  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(t);
  });

  // Reading the conversation starts disappearing timers and clears unread.
  $effect(() => {
    void messages.length;
    if (conv && conv.unread > 0 && document.visibilityState === 'visible') {
      void chat.client?.markRead(convId);
    }
  });

  // Keep the newest message in view.
  $effect(() => {
    void messages.length;
    queueMicrotask(() => list?.scrollTo({ top: list.scrollHeight }));
  });

  $effect(() => {
    void chat.version;
    const peer = conv?.peer;
    if (peer) void chat.client?.identity(peer).then((r) => (identity = r));
    else identity = undefined;
  });

  async function run(action: () => Promise<unknown>) {
    error = '';
    blockedBy = null;
    try {
      await action();
      return true;
    } catch (err) {
      if (err instanceof IdentityChangedError) blockedBy = err.username;
      else if (err instanceof ChatInputError) error = err.message;
      else error = 'Could not send. Check your connection and try again.';
      return false;
    }
  }

  async function send(e?: SubmitEvent) {
    e?.preventDefault();
    const text = draft.trim();
    if (!text || sending) return;
    sending = true;
    if (await run(() => chat.client!.sendText(convId, text))) draft = '';
    sending = false;
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      void send();
    }
  }

  async function attach(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    uploading = 0;
    await run(async () => {
      const ref = await uploadAttachment(file, (d, t) => (uploading = t ? d / t : 1));
      await chat.client!.sendFile(convId, ref);
    });
    uploading = null;
  }

  async function download(m: StoredMessage) {
    if (!m.file) return;
    downloading[m.id] = 0;
    try {
      await downloadAttachment(m.file, (d, t) => (downloading[m.id] = t ? d / t : 1));
    } catch {
      error = 'That file has expired or could not be decrypted. Shared files last 24 hours.';
    } finally {
      delete downloading[m.id];
    }
  }

  async function acceptKey() {
    if (!blockedBy) return;
    const u = blockedBy;
    await chat.client!.acceptNewIdentity(u);
    blockedBy = null;
    showSafety = true;
  }

  const time = (ts: number) =>
    new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
</script>

{#if conv}
  <section class="flex h-full min-h-0 flex-col" aria-label="Conversation with {conv.title}">
    <header class="flex items-center gap-3 border-b border-neutral-800 px-4 py-3">
      <button
        type="button"
        class="text-neutral-400 hover:text-neutral-100 md:hidden"
        onclick={onBack}
        aria-label="Back to conversations">←</button
      >
      <div class="min-w-0 flex-1">
        <h2 class="truncate font-semibold text-neutral-50" data-testid="conv-title">
          {conv.kind === 'direct' ? `@${conv.title}` : conv.title}
        </h2>
        <p class="truncate text-xs text-neutral-500">
          {#if conv.kind === 'group'}{conv.members.length} members ·
          {/if}{conv.timer
            ? `⏱ messages disappear after ${timerLabel(conv.timer)}`
            : 'Disappearing messages off'}
          {#if identity?.verified}
            · ✓ verified{/if}
        </p>
      </div>
      <label class="sr-only" for="timer">Disappearing messages</label>
      <select
        id="timer"
        class="max-w-28 shrink-0 rounded-lg border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs"
        value={conv.timer}
        disabled={conv.left}
        onchange={(e) => run(() => chat.client!.setTimer(convId, Number(e.currentTarget.value)))}
      >
        {#each DISAPPEARING_TIMER_OPTIONS_SECONDS as s (s)}
          <option value={s}>⏱ {s ? timerLabel(s) : 'Off'}</option>
        {/each}
      </select>
      <div class="relative">
        <button
          type="button"
          class="rounded-lg px-2 py-1 text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100"
          aria-label="Conversation menu"
          aria-expanded={showMenu}
          onclick={() => (showMenu = !showMenu)}>⋯</button
        >
        {#if showMenu}
          <div
            class="absolute right-0 z-10 mt-1 w-56 rounded-lg border border-neutral-700 bg-neutral-900 p-1 text-sm shadow-xl"
          >
            {#if conv.peer}
              {@const peer = conv.peer}
              <button
                type="button"
                class="block w-full rounded px-3 py-2 text-left hover:bg-neutral-800"
                onclick={() => ((showSafety = true), (showMenu = false))}>Safety number</button
              >
              <button
                type="button"
                class="block w-full rounded px-3 py-2 text-left hover:bg-neutral-800"
                onclick={() => ((showMenu = false), run(() => chat.client!.resetSession(peer)))}
                >Reset secure session</button
              >
            {:else if !conv.left}
              <button
                type="button"
                class="block w-full rounded px-3 py-2 text-left hover:bg-neutral-800"
                onclick={() => ((showMenu = false), run(() => chat.client!.leaveGroup(convId)))}
                >Leave group</button
              >
            {/if}
            <button
              type="button"
              class="block w-full rounded px-3 py-2 text-left text-red-400 hover:bg-neutral-800"
              onclick={() => {
                showMenu = false;
                void chat.client!.deleteConversation(convId).then(onBack);
              }}>Delete chat from this device</button
            >
          </div>
        {/if}
      </div>
    </header>

    {#if conv.kind === 'group'}
      <p class="border-b border-neutral-800 px-4 py-2 text-xs text-neutral-500">
        {conv.members.map((m) => `@${m}`).join(', ')}
      </p>
    {/if}

    {#if identity?.changed && conv.peer}
      <div
        class="flex flex-wrap items-center gap-2 bg-amber-500/10 px-4 py-2 text-sm text-amber-200"
        role="alert"
      >
        Your safety number with @{conv.peer} changed. They may have reinstalled, or someone may be intercepting.
        <button type="button" class="underline" onclick={() => (showSafety = true)}>Check it</button
        >
      </div>
    {/if}
    {#if blockedBy}
      <div
        class="flex flex-wrap items-center gap-2 bg-red-500/10 px-4 py-2 text-sm text-red-300"
        role="alert"
      >
        You had verified @{blockedBy}, but their key changed. Nothing was sent.
        <button type="button" class="underline" onclick={acceptKey}
          >Accept the new key and verify again</button
        >
      </div>
    {/if}

    {#if showSafety && conv.peer}
      <div class="max-h-[75%] shrink-0 overflow-y-auto border-b border-neutral-800 p-4">
        <SafetyNumber username={conv.peer} onClose={() => (showSafety = false)} />
      </div>
    {/if}

    <ol
      bind:this={list}
      class="min-h-0 flex-1 space-y-2 overflow-y-auto px-4 py-4"
      data-testid="messages"
    >
      {#each messages as m (m.id)}
        {#if m.kind === 'system'}
          <li class="text-center text-xs text-neutral-500">{m.text}</li>
        {:else}
          {@const mine = m.from === me}
          <li class={['flex', mine ? 'justify-end' : 'justify-start']} data-testid="message">
            <div
              class={[
                'max-w-[80%] rounded-2xl px-3.5 py-2 text-sm',
                mine ? 'bg-emerald-600/30 text-neutral-50' : 'bg-neutral-800 text-neutral-100',
              ]}
            >
              {#if conv.kind === 'group' && !mine}
                <p class="mb-0.5 text-xs font-medium text-emerald-300">@{m.from}</p>
              {/if}
              {#if m.file}
                <div class="flex items-center gap-3">
                  <div class="min-w-0">
                    <p class="truncate font-medium">📎 {m.file.name}</p>
                    <p class="text-xs text-neutral-400">{formatBytes(m.file.size)} · 24 h link</p>
                  </div>
                  <button
                    type="button"
                    class="shrink-0 rounded-lg bg-neutral-950/40 px-2.5 py-1 text-xs hover:bg-neutral-950/70"
                    disabled={m.id in downloading}
                    onclick={() => download(m)}
                  >
                    {m.id in downloading ? `${Math.floor(downloading[m.id]! * 100)}%` : 'Download'}
                  </button>
                </div>
              {/if}
              {#if m.text}<p class="break-words whitespace-pre-wrap" data-testid="message-text">
                  {m.text}
                </p>{/if}
              <p class="mt-0.5 text-right text-[10px] text-neutral-400">
                {time(m.sentAt)}
                {#if m.expiresAt}
                  · ⏱ {m.readAt === undefined && !mine
                    ? 'unread'
                    : formatRemaining(m.expiresAt - now)}
                {/if}
              </p>
            </div>
          </li>
        {/if}
      {:else}
        <li class="pt-10 text-center text-sm text-neutral-500">
          No messages yet. Everything you send is end-to-end encrypted.
        </li>
      {/each}
    </ol>

    {#if error}<p role="alert" class="px-4 pb-1 text-sm text-red-400">{error}</p>{/if}
    {#if conv.left}
      <p class="border-t border-neutral-800 px-4 py-3 text-sm text-neutral-500">
        You left this group.
      </p>
    {:else}
      <form class="flex items-end gap-2 border-t border-neutral-800 p-3" onsubmit={send}>
        <label
          class="cursor-pointer rounded-lg px-2 py-2 text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100"
          title="Attach a file (encrypted, expires in 24 h)"
        >
          {uploading === null ? '📎' : `${Math.floor(uploading * 100)}%`}
          <span class="sr-only">Attach a file</span>
          <input type="file" class="sr-only" disabled={uploading !== null} onchange={attach} />
        </label>
        <textarea
          bind:value={draft}
          onkeydown={onKey}
          rows="1"
          placeholder="Encrypted message"
          aria-label="Message"
          class="max-h-40 min-h-10 flex-1 resize-none rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-neutral-100"
        ></textarea>
        <button
          type="submit"
          disabled={!draft.trim() || sending}
          class="rounded-xl bg-emerald-500 px-4 py-2 text-sm font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40"
          >Send</button
        >
      </form>
    {/if}
  </section>
{/if}
