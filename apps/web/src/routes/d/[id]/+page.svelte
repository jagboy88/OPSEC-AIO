<script lang="ts">
  import { page } from '$app/state';
  import { replaceState } from '$app/navigation';
  import { resolve } from '$app/paths';
  import {
    DecryptionError,
    fromBase64Url,
    isValidId,
    isValidToken,
    openDropHeader,
    parseFragment,
    ready,
    wipe,
    type OpenedDrop,
  } from '@opsec-aio/crypto';
  import { ApiError, api } from '#lib/api.js';
  import Countdown from '#lib/components/Countdown.svelte';
  import {
    MEMORY_WARNING_THRESHOLD,
    STREAM_TO_DISK_THRESHOLD,
    canStreamToDisk,
    diskSink,
    downloadDrop,
    memorySink,
    type FileSink,
  } from '#lib/drop.js';
  import { formatBytes, pluralize } from '#lib/format.js';

  interface Info {
    expiresAt: string;
    downloadsRemaining: number | null;
  }
  type View =
    | { kind: 'invalid' }
    | { kind: 'loading' }
    | { kind: 'locked'; info: Info; unlock: (pw: string) => Promise<OpenedDrop> }
    | { kind: 'ready'; info: Info; opened: OpenedDrop }
    | { kind: 'downloading'; info: Info; name: string; progress: number }
    | { kind: 'saved'; name: string; remaining: number | null }
    | { kind: 'gone' }
    | { kind: 'undecryptable' }
    | { kind: 'error'; message: string }
    | { kind: 'delete-confirm' }
    | { kind: 'deleted' };

  const id = $derived(page.params.id ?? '');

  // Secrets from the fragment live only in memory on this page.
  let key: Uint8Array | null = null;
  let deletionToken: string | null = null;
  let view = $state<View>({ kind: 'loading' });

  function readFragment(): View | null {
    const hash = location.hash.slice(1);
    if (!isValidId(id) || !hash) return { kind: 'invalid' };
    if (hash.startsWith('del.')) {
      const token = hash.slice(4);
      if (!isValidToken(token)) return { kind: 'invalid' };
      deletionToken = token;
      return { kind: 'delete-confirm' };
    }
    try {
      key = parseFragment(hash).key;
      return null;
    } catch {
      return { kind: 'invalid' };
    }
  }

  async function load() {
    if (!key) return;
    view = { kind: 'loading' };
    try {
      await ready();
      const meta = await api.dropMeta(id);
      const info: Info = {
        expiresAt: meta.expires_at,
        downloadsRemaining: meta.downloads_remaining,
      };
      let header;
      try {
        header = await openDropHeader(key, fromBase64Url(meta.header_blob));
      } catch {
        view = { kind: 'undecryptable' };
        return;
      }
      view = header.locked
        ? { kind: 'locked', info, unlock: header.unlock }
        : { kind: 'ready', info, opened: header };
    } catch (err) {
      view =
        err instanceof ApiError && err.status === 404
          ? { kind: 'gone' }
          : err instanceof ApiError && err.code === 'rate_limited'
            ? { kind: 'error', message: 'Too many attempts. Wait a minute and try again.' }
            : { kind: 'error', message: 'Could not reach the server. Check your connection.' };
    }
  }

  function reinitialise() {
    if (key) wipe(key);
    key = null;
    deletionToken = null;
    const v = readFragment();
    if (v) view = v;
    else void load();
  }

  // Initial load, and re-read on in-page navigation (new fragment or new id).
  let shownId: string | undefined;
  $effect(() => {
    const current = id;
    if (current !== shownId) {
      shownId = current;
      reinitialise();
    }
  });
  $effect(() => {
    const onHashChange = () => {
      if (location.hash) reinitialise();
    };
    addEventListener('hashchange', onHashChange);
    return () => {
      removeEventListener('hashchange', onHashChange);
      if (key) wipe(key);
    };
  });

  let password = $state('');
  let unlocking = $state(false);
  let unlockError = $state('');

  async function unlock(e: SubmitEvent) {
    e.preventDefault();
    if (view.kind !== 'locked' || !password) return;
    unlocking = true;
    unlockError = '';
    await new Promise((r) => setTimeout(r, 30)); // paint before Argon2id blocks
    try {
      const opened = await view.unlock(password);
      view = { kind: 'ready', info: view.info, opened };
      password = '';
    } catch (err) {
      unlockError =
        err instanceof DecryptionError
          ? 'Wrong password. Try again.'
          : 'This file was made with a newer version of OpSec AIO.';
    } finally {
      unlocking = false;
    }
  }

  const streamsToDisk = (o: OpenedDrop) =>
    o.meta.size > STREAM_TO_DISK_THRESHOLD && canStreamToDisk();

  async function download() {
    if (view.kind !== 'ready') return;
    const { opened, info } = view;
    let sink: FileSink;
    if (streamsToDisk(opened)) {
      try {
        sink = await diskSink(opened.meta.name); // must run in the click handler
      } catch {
        return; // save dialog dismissed
      }
    } else {
      sink = memorySink(opened.meta.name, opened.meta.type);
    }
    view = { kind: 'downloading', info, name: opened.meta.name, progress: 0 };
    try {
      const remaining = await downloadDrop(id, opened, sink, (done, total) => {
        if (view.kind === 'downloading') view.progress = total ? done / total : 1;
      });
      void replaceState(resolve('/d/[id]', { id }), {});
      view = { kind: 'saved', name: opened.meta.name, remaining };
    } catch (err) {
      view =
        err instanceof ApiError && err.status === 404
          ? { kind: 'gone' }
          : err instanceof DecryptionError
            ? { kind: 'undecryptable' }
            : { kind: 'error', message: 'The download failed part-way. Nothing was saved.' };
    }
  }

  async function deleteFile() {
    if (!deletionToken) return;
    try {
      await api.deleteDrop(id, { deletion_token: deletionToken });
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 404)) {
        view = { kind: 'error', message: 'Deletion failed. Try again.' };
        return;
      }
    }
    void replaceState(resolve('/d/[id]', { id }), {});
    deletionToken = null;
    view = { kind: 'deleted' };
  }

  const card = 'mt-6 rounded-xl border border-neutral-800 bg-neutral-900 p-6';
  const primary =
    'rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40';
  const secondary = 'rounded-lg bg-neutral-800 px-4 py-2.5 text-neutral-100 hover:bg-neutral-700';
</script>

<svelte:head><title>Encrypted file · OpSec AIO</title></svelte:head>

<h1 class="mt-6 text-2xl font-semibold text-neutral-50">Encrypted file</h1>

{#snippet infoLine(info: Info)}
  <p class="mt-1 text-sm text-neutral-400">
    Deleted in <Countdown until={info.expiresAt} />{info.downloadsRemaining === null
      ? ''
      : ` or after ${pluralize(info.downloadsRemaining, 'more download')}`}.
  </p>
{/snippet}

<div aria-live="polite" data-testid="drop-view" data-state={view.kind}>
  {#if view.kind === 'invalid'}
    <div class={card}>
      <p class="font-medium text-neutral-100">This link is incomplete.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The key is the part after the <code>#</code>. Some apps cut it off. Ask the sender to send
        the full link again.
      </p>
    </div>
  {:else if view.kind === 'loading'}
    <div class={card}><p class="text-neutral-400">Decrypting file details…</p></div>
  {:else if view.kind === 'locked'}
    <form class={card} onsubmit={unlock}>
      <p class="font-medium text-neutral-100">This file is password-protected.</p>
      {@render infoLine(view.info)}
      <div class="mt-4 flex flex-wrap gap-2">
        <input
          type="password"
          bind:value={password}
          aria-label="Password"
          autocomplete="off"
          class="min-w-0 flex-1 rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2"
        />
        <button type="submit" class={primary} disabled={!password || unlocking}>
          {unlocking ? 'Checking…' : 'Unlock'}
        </button>
      </div>
      {#if unlockError}<p role="alert" class="mt-2 text-sm text-red-400">{unlockError}</p>{/if}
    </form>
  {:else if view.kind === 'ready'}
    <div class={card}>
      <p class="font-medium break-all text-neutral-100" data-testid="file-name">
        {view.opened.meta.name}
      </p>
      <p class="text-sm text-neutral-300">{formatBytes(view.opened.meta.size)}</p>
      {@render infoLine(view.info)}
      {#if view.opened.meta.size > MEMORY_WARNING_THRESHOLD && !streamsToDisk(view.opened)}
        <p class="mt-3 text-sm text-amber-300">
          This browser has to hold the whole file in memory while decrypting it. Very large files
          can fail on phones; desktop Chrome or Edge can save straight to disk instead.
        </p>
      {/if}
      <div class="mt-5 flex flex-wrap gap-3">
        <button type="button" class={primary} onclick={download}>Download & decrypt</button>
      </div>
      <p class="mt-3 text-xs text-neutral-500">
        Decrypted in this browser. The server only ever sees encrypted chunks.
      </p>
    </div>
  {:else if view.kind === 'downloading'}
    <div class={card} role="status">
      <p class="font-medium break-all text-neutral-100">{view.name}</p>
      <progress
        class="progress-bar mt-4"
        value={Math.round(view.progress * 1000)}
        max="1000"
        aria-label="Download progress"
      ></progress>
      <p class="mt-2 text-sm text-neutral-400">
        Downloading and decrypting… {Math.floor(view.progress * 100)}%
      </p>
    </div>
  {:else if view.kind === 'saved'}
    <div class={card} role="status">
      <p class="font-medium text-emerald-400">Decrypted and saved.</p>
      <p class="mt-1 text-sm break-all text-neutral-300" data-testid="saved-name">{view.name}</p>
      <p class="mt-2 text-sm text-neutral-400">
        {#if view.remaining === 0}
          That was the last allowed download. The file is now deleted from the server.
        {:else if view.remaining === null}
          Anyone with the link can still download it until it expires.
        {:else}
          It can be downloaded {pluralize(view.remaining, 'more time')}.
        {/if}
      </p>
      {#if view.remaining !== 0}
        <button type="button" class="mt-4 {secondary}" onclick={load}>Download again</button>
      {/if}
    </div>
  {:else if view.kind === 'gone'}
    <div class={card}>
      <p class="font-medium text-neutral-100">There's nothing here.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The file has expired, reached its download limit, was deleted, or never existed. OpSec AIO
        can't tell these apart, by design.
      </p>
      <a href={resolve('/drop')} class="mt-4 inline-block text-sm text-emerald-400 hover:underline"
        >Send a file →</a
      >
    </div>
  {:else if view.kind === 'undecryptable'}
    <div class={card}>
      <p class="font-medium text-red-400">This file could not be decrypted.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The link is damaged or doesn't belong to this file, or the data was tampered with.
      </p>
    </div>
  {:else if view.kind === 'error'}
    <div class={card}><p role="alert" class="text-red-400">{view.message}</p></div>
  {:else if view.kind === 'delete-confirm'}
    <div class={card}>
      <p class="text-lg font-medium text-neutral-100">Delete this file?</p>
      <p class="mt-2 text-sm text-neutral-400">
        This is a deletion link. The encrypted file will be removed from the server now.
      </p>
      <div class="mt-5 flex gap-3">
        <button
          type="button"
          class="rounded-lg bg-red-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-red-400"
          onclick={deleteFile}>Delete file</button
        >
        <a href={resolve('/')} class={secondary}>Cancel</a>
      </div>
    </div>
  {:else if view.kind === 'deleted'}
    <div class={card}>
      <p class="font-medium text-neutral-100">Deleted.</p>
      <p class="mt-2 text-sm text-neutral-400">
        If the file still existed, it's gone now and the share link no longer works.
      </p>
    </div>
  {/if}
</div>
