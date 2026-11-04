<script lang="ts">
  import { page } from '$app/state';
  import { replaceState } from '$app/navigation';
  import { resolve } from '$app/paths';
  import {
    DecryptionError,
    decryptNote,
    fromBase64Url,
    isValidId,
    isValidToken,
    parseFragment,
    ready,
    wipe,
  } from '@opsec-aio/crypto';
  import { ApiError, api } from '#lib/api.js';
  import { pluralize } from '#lib/format.js';

  type View =
    | { kind: 'invalid' }
    | { kind: 'confirm'; passwordHint: boolean }
    | { kind: 'opening' }
    | { kind: 'locked'; unlock: (pw: string) => Promise<string>; remaining: number }
    | { kind: 'shown'; text: string; remaining: number }
    | { kind: 'gone' }
    | { kind: 'undecryptable' }
    | { kind: 'error'; message: string }
    | { kind: 'delete-confirm' }
    | { kind: 'deleted' };

  const id = $derived(page.params.id ?? '');

  // Everything secret comes from the fragment, read on arrival and then held
  // only in memory.
  let key: Uint8Array | null = null;
  let deletionToken: string | null = null;
  let view = $state<View>(initialView());

  function reinitialise() {
    if (key) wipe(key);
    key = null;
    deletionToken = null;
    view = initialView();
  }

  // A link that differs only after '#' (or a different note id) is an in-page
  // navigation: no reload happens, so re-read the fragment explicitly.
  $effect(() => {
    const onHashChange = () => {
      if (location.hash) reinitialise();
    };
    addEventListener('hashchange', onHashChange);
    return () => removeEventListener('hashchange', onHashChange);
  });
  let shownId: string | undefined;
  $effect(() => {
    const current = id;
    if (shownId !== undefined && current !== shownId) reinitialise();
    shownId = current;
  });

  function initialView(): View {
    const hash = location.hash.slice(1);
    if (!isValidId(id) || !hash) return { kind: 'invalid' };
    if (hash.startsWith('del.')) {
      const token = hash.slice(4);
      if (!isValidToken(token)) return { kind: 'invalid' };
      deletionToken = token;
      return { kind: 'delete-confirm' };
    }
    try {
      const secret = parseFragment(hash);
      key = secret.key;
      return { kind: 'confirm', passwordHint: secret.flags.includes('p') };
    } catch {
      return { kind: 'invalid' };
    }
  }

  /** Remove the key from the address bar and history once it has been used. */
  function forgetFragment() {
    void replaceState(resolve('/n/[id]', { id }), {});
  }

  async function openNote() {
    if (!key) return;
    view = { kind: 'opening' };
    try {
      await ready();
      const res = await api.openNote(id);
      forgetFragment();
      let opened;
      try {
        opened = await decryptNote(key, fromBase64Url(res.ciphertext));
      } catch {
        view = { kind: 'undecryptable' };
        return;
      } finally {
        wipe(key);
        key = null;
      }
      view = opened.locked
        ? { kind: 'locked', unlock: opened.unlock, remaining: res.views_remaining }
        : { kind: 'shown', text: opened.text, remaining: res.views_remaining };
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        forgetFragment();
        view = { kind: 'gone' };
      } else if (err instanceof ApiError && err.code === 'rate_limited') {
        view = { kind: 'error', message: 'Too many attempts. Wait a minute and try again.' };
      } else {
        view = {
          kind: 'error',
          message: 'Could not reach the server. The note has not been opened. Try again.',
        };
      }
    }
  }

  let password = $state('');
  let unlockError = $state('');
  let unlocking = $state(false);

  async function unlock(e: SubmitEvent) {
    e.preventDefault();
    if (view.kind !== 'locked' || !password) return;
    unlocking = true;
    unlockError = '';
    await new Promise((r) => setTimeout(r, 30)); // paint before Argon2id blocks
    try {
      const text = await view.unlock(password);
      view = { kind: 'shown', text, remaining: view.remaining };
      password = '';
    } catch (err) {
      unlockError =
        err instanceof DecryptionError
          ? 'Wrong password. You can try again: the note stays on this page until you leave.'
          : 'This note was made with a newer version of OpSec AIO.';
    } finally {
      unlocking = false;
    }
  }

  async function deleteNote() {
    if (!deletionToken) return;
    try {
      await api.deleteNote(id, deletionToken);
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 404)) {
        view = { kind: 'error', message: 'Deletion failed. Try again.' };
        return;
      }
    }
    forgetFragment();
    deletionToken = null;
    view = { kind: 'deleted' };
  }

  let copied = $state(false);
  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      /* clipboard blocked; the text is selectable on screen */
    }
  }

  function clearScreen() {
    view = { kind: 'gone' };
  }

  // Drop decrypted text from memory when leaving the page.
  $effect(() => () => {
    view = { kind: 'gone' };
    if (key) wipe(key);
  });

  const card = 'mt-6 rounded-xl border border-neutral-800 bg-neutral-900 p-6';
  const primary =
    'rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40';
  const secondary = 'rounded-lg bg-neutral-800 px-4 py-2.5 text-neutral-100 hover:bg-neutral-700';
</script>

<svelte:head><title>Secure note · OpSec AIO</title></svelte:head>

<h1 class="mt-6 text-2xl font-semibold text-neutral-50">Secure note</h1>

<div aria-live="polite" data-testid="note-view" data-state={view.kind}>
  {#if view.kind === 'invalid'}
    <div class={card}>
      <p class="font-medium text-neutral-100">This link is incomplete.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The key is the part after the <code>#</code>. Some apps cut it off. Ask the sender to send
        the full link again.
      </p>
    </div>
  {:else if view.kind === 'confirm'}
    <div class={card}>
      <p class="text-lg font-medium text-neutral-100">
        This note will be destroyed when you open it.
      </p>
      <p class="mt-2 text-sm text-neutral-400">
        Make sure you're ready to read it now. It will be decrypted in this browser and removed from
        the server.
      </p>
      {#if view.passwordHint}
        <p class="mt-2 text-sm text-amber-300">
          It is password-protected. Have the password ready: once opened, the note only lives on
          this page until you leave.
        </p>
      {/if}
      <div class="mt-5 flex flex-wrap gap-3">
        <button type="button" class={primary} onclick={openNote}>Open and destroy note</button>
        <a href={resolve('/')} class={secondary}>Not now</a>
      </div>
    </div>
  {:else if view.kind === 'opening'}
    <div class={card}><p class="text-neutral-400">Opening…</p></div>
  {:else if view.kind === 'locked'}
    <form class={card} onsubmit={unlock}>
      <p class="font-medium text-neutral-100">Enter the password to read the note.</p>
      <p class="mt-1 text-sm text-neutral-400">
        The encrypted note has been removed from the server and is held only on this page.
      </p>
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
  {:else if view.kind === 'shown'}
    <div class={card}>
      <pre
        data-testid="note-text"
        class="font-mono text-sm break-words whitespace-pre-wrap text-neutral-100">{view.text}</pre>
    </div>
    <p class="mt-3 text-sm text-neutral-400" role="status">
      {#if view.remaining === 0}
        This note has now been destroyed on the server. Copy anything you need before leaving.
      {:else}
        It can be opened {pluralize(view.remaining, 'more time')} before it is destroyed.
      {/if}
    </p>
    <div class="mt-4 flex flex-wrap gap-3">
      <button
        type="button"
        class={secondary}
        onclick={() => copyText(view.kind === 'shown' ? view.text : '')}
      >
        {copied ? 'Copied' : 'Copy note'}
      </button>
      <button type="button" class={secondary} onclick={clearScreen}>Clear from screen</button>
      <span class="sr-only" aria-live="polite">{copied ? 'Copied to clipboard' : ''}</span>
    </div>
  {:else if view.kind === 'gone'}
    <div class={card}>
      <p class="font-medium text-neutral-100">There's nothing here.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The note has already been read, has expired, was deleted, or never existed. OpSec AIO can't
        tell these apart, by design.
      </p>
      <a href={resolve('/burn')} class="mt-4 inline-block text-sm text-emerald-400 hover:underline"
        >Write a new note →</a
      >
    </div>
  {:else if view.kind === 'undecryptable'}
    <div class={card}>
      <p class="font-medium text-red-400">This note could not be decrypted.</p>
      <p class="mt-2 text-sm text-neutral-400">
        The link is damaged or doesn't belong to this note. The note has been removed from the
        server either way.
      </p>
    </div>
  {:else if view.kind === 'error'}
    <div class={card}>
      <p role="alert" class="text-red-400">{view.message}</p>
    </div>
  {:else if view.kind === 'delete-confirm'}
    <div class={card}>
      <p class="text-lg font-medium text-neutral-100">Delete this note?</p>
      <p class="mt-2 text-sm text-neutral-400">
        This is a deletion link. The note will be destroyed without being opened.
      </p>
      <div class="mt-5 flex gap-3">
        <button
          type="button"
          class="rounded-lg bg-red-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-red-400"
          onclick={deleteNote}>Delete note</button
        >
        <a href={resolve('/')} class={secondary}>Cancel</a>
      </div>
    </div>
  {:else if view.kind === 'deleted'}
    <div class={card}>
      <p class="font-medium text-neutral-100">Deleted.</p>
      <p class="mt-2 text-sm text-neutral-400">
        If the note still existed, it's gone now and the share link no longer works.
      </p>
    </div>
  {/if}
</div>
