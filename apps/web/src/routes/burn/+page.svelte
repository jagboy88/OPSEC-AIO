<script lang="ts">
  import {
    buildShareLink,
    encryptNote,
    ready,
    toBase64Url,
    utf8Encode,
    wipe,
  } from '@opsec-aio/crypto';
  import {
    NOTE_DEFAULT_MAX_VIEWS,
    NOTE_DEFAULT_TTL_SECONDS,
    NOTE_EXPIRY_OPTIONS_SECONDS,
    NOTE_MAX_PLAINTEXT_BYTES,
    NOTE_MAX_VIEWS,
  } from '@opsec-aio/types';
  import { ApiError, api } from '#lib/api.js';
  import CopyField from '#lib/components/CopyField.svelte';
  import Countdown from '#lib/components/Countdown.svelte';
  import QrCode from '#lib/components/QrCode.svelte';
  import WhoCanRead from '#lib/components/WhoCanRead.svelte';
  import { formatBytes, pluralize } from '#lib/format.js';

  const EXPIRY_LABELS: Record<number, string> = {
    3600: '1 hour',
    86400: '1 day',
    604800: '7 days',
    2592000: '30 days',
  };

  let text = $state('');
  let expiresIn = $state<number>(NOTE_DEFAULT_TTL_SECONDS);
  let maxViews = $state<number>(NOTE_DEFAULT_MAX_VIEWS);
  let usePassword = $state(false);
  let password = $state('');

  let busy = $state<false | 'encrypting' | 'deriving' | 'uploading'>(false);
  let error = $state('');

  interface Created {
    id: string;
    link: string;
    deleteLink: string;
    deletionToken: string;
    expiresAt: string;
    maxViews: number;
    passwordProtected: boolean;
  }
  let created = $state<Created | null>(null);
  let deleteState = $state<'idle' | 'confirm' | 'deleting' | 'deleted' | 'failed'>('idle');

  const bytes = $derived(utf8Encode(text).length);
  const tooLong = $derived(bytes > NOTE_MAX_PLAINTEXT_BYTES);
  const canSubmit = $derived(
    !busy && text.trim().length > 0 && !tooLong && (!usePassword || password.length > 0),
  );

  /** Let the browser paint a status before a CPU-heavy step (Argon2id). */
  const paint = () => new Promise((r) => setTimeout(r, 30));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    error = '';
    try {
      busy = usePassword ? 'deriving' : 'encrypting';
      await paint();
      await ready();
      const { key, ciphertext } = await encryptNote(text, usePassword ? { password } : {});
      busy = 'uploading';
      const res = await api.createNote({
        ciphertext: toBase64Url(ciphertext),
        expires_in: expiresIn,
        max_views: maxViews,
      });
      const flags = usePassword ? ['p'] : [];
      created = {
        id: res.note_id,
        link: buildShareLink(location.origin, 'n', res.note_id, key, flags),
        deleteLink: `${location.origin}/n/${res.note_id}#del.${res.deletion_token}`,
        deletionToken: res.deletion_token,
        expiresAt: res.expires_at,
        maxViews,
        passwordProtected: usePassword,
      };
      wipe(key);
      // Don't keep the plaintext or password around once it's been sealed.
      text = '';
      password = '';
      deleteState = 'idle';
    } catch (err) {
      error =
        err instanceof ApiError && err.code === 'rate_limited'
          ? 'Too many notes from this connection. Try again later.'
          : err instanceof ApiError && err.code === 'network'
            ? 'Could not reach the server. Check your connection.'
            : 'Something went wrong creating the note. Nothing was saved.';
    } finally {
      busy = false;
    }
  }

  async function deleteNow() {
    if (!created) return;
    deleteState = 'deleting';
    try {
      await api.deleteNote(created.id, created.deletionToken);
      deleteState = 'deleted';
    } catch (err) {
      // 404 means it was already read or expired: either way it's gone.
      deleteState = err instanceof ApiError && err.status === 404 ? 'deleted' : 'failed';
    }
  }

  function reset() {
    created = null;
    deleteState = 'idle';
    usePassword = false;
  }
</script>

<svelte:head><title>Burn · OpSec AIO</title></svelte:head>

<h1 class="mt-6 text-2xl font-semibold text-neutral-50">Burn after reading</h1>
<p class="mt-2 max-w-2xl text-sm text-neutral-400">
  Write a note and get a link. The note is encrypted in this browser and destroyed the moment it is
  read.
</p>

{#if !created}
  <form class="mt-6 grid gap-6 lg:grid-cols-[1fr_20rem]" onsubmit={submit}>
    <div>
      <label for="note" class="mb-1 block text-sm font-medium text-neutral-200">Your note</label>
      <textarea
        id="note"
        bind:value={text}
        rows="12"
        required
        spellcheck="false"
        autocomplete="off"
        placeholder="Paste a password, an address, anything that shouldn't sit in a chat log…"
        aria-describedby="note-size"
        class="w-full resize-y rounded-xl border border-neutral-700 bg-neutral-900 p-4 font-mono text-sm text-neutral-100 placeholder:text-neutral-600"
      ></textarea>
      <p
        id="note-size"
        class={['mt-1 text-right text-xs', tooLong ? 'text-red-400' : 'text-neutral-500']}
      >
        {formatBytes(bytes)} / {formatBytes(NOTE_MAX_PLAINTEXT_BYTES)}
      </p>
    </div>

    <div class="space-y-5">
      <div>
        <label for="expiry" class="mb-1 block text-sm font-medium text-neutral-200"
          >If nobody opens it, delete after</label
        >
        <select
          id="expiry"
          bind:value={expiresIn}
          class="w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm"
        >
          {#each NOTE_EXPIRY_OPTIONS_SECONDS as s (s)}
            <option value={s}>{EXPIRY_LABELS[s]}</option>
          {/each}
        </select>
      </div>

      <div>
        <label for="views" class="mb-1 block text-sm font-medium text-neutral-200"
          >Destroy after</label
        >
        <select
          id="views"
          bind:value={maxViews}
          class="w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm"
        >
          {#each Array.from({ length: NOTE_MAX_VIEWS }, (_, i) => i + 1) as n (n)}
            <option value={n}>{pluralize(n, 'view')}</option>
          {/each}
        </select>
      </div>

      <div>
        <label class="flex items-center gap-2 text-sm text-neutral-200">
          <input type="checkbox" bind:checked={usePassword} class="size-4 accent-emerald-500" />
          Also require a password
        </label>
        {#if usePassword}
          <input
            type="password"
            bind:value={password}
            autocomplete="new-password"
            aria-label="Password"
            placeholder="Password"
            class="mt-2 w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm"
          />
          <p class="mt-1 text-xs text-neutral-500">
            Send the password through a different channel than the link.
          </p>
        {/if}
      </div>

      <button
        type="submit"
        disabled={!canSubmit}
        class="w-full rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {#if busy === 'deriving'}Strengthening password…
        {:else if busy === 'encrypting'}Encrypting…
        {:else if busy === 'uploading'}Uploading ciphertext…
        {:else}Create secure link{/if}
      </button>
      {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
    </div>
  </form>
{:else}
  <section class="mt-6 grid gap-6 lg:grid-cols-[1fr_16rem]" aria-labelledby="ready-heading">
    <div class="space-y-5">
      <h2 id="ready-heading" class="text-lg font-semibold text-emerald-400">Your link is ready</h2>

      {#if deleteState === 'deleted'}
        <p class="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-sm" role="status">
          The note has been deleted. The link no longer works.
        </p>
      {:else}
        <CopyField value={created.link} label="Share this link" testid="share-link" />
        <p class="text-sm text-neutral-400">
          Can be opened {pluralize(created.maxViews, 'time')}. Deleted in
          <Countdown until={created.expiresAt} /> if not.
          {#if created.passwordProtected}The recipient will also need the password.{/if}
        </p>
      {/if}

      <WhoCanRead
        rows={[
          {
            who: created.passwordProtected
              ? 'Whoever has this link and the password'
              : 'Whoever has this link',
            can: true,
            detail: `until it has been opened ${pluralize(created.maxViews, 'time')}. The key is the part after #, which never reaches the server.`,
          },
          {
            who: 'OpSec AIO servers',
            can: false,
            detail:
              'they hold an encrypted blob, its size rounded up to 1 KB, its expiry time and its view count. No key, no text.',
          },
          {
            who: 'Anyone who sees the link later',
            can: false,
            detail: 'once the note has been read, there is nothing left to open.',
          },
        ]}
      />

      {#if deleteState !== 'deleted'}
        <details class="rounded-xl border border-neutral-800 p-4 text-sm">
          <summary class="cursor-pointer font-medium text-neutral-200">Delete it early</summary>
          <div class="mt-3 space-y-3">
            <p class="text-neutral-400">
              Save this deletion link if you might want to cancel the note after leaving this page.
              It is shown only once.
            </p>
            <CopyField value={created.deleteLink} label="Deletion link" testid="delete-link" />
            {#if deleteState === 'confirm' || deleteState === 'deleting'}
              <div class="flex gap-2">
                <button
                  type="button"
                  onclick={deleteNow}
                  disabled={deleteState === 'deleting'}
                  class="rounded-lg bg-red-500 px-3 py-2 font-medium text-neutral-950 hover:bg-red-400"
                  >Yes, delete it now</button
                >
                <button
                  type="button"
                  onclick={() => (deleteState = 'idle')}
                  class="rounded-lg bg-neutral-800 px-3 py-2">Cancel</button
                >
              </div>
            {:else}
              <button
                type="button"
                onclick={() => (deleteState = 'confirm')}
                class="rounded-lg border border-red-500/40 px-3 py-2 text-red-400 hover:bg-red-500/10"
                >Delete now</button
              >
            {/if}
            {#if deleteState === 'failed'}
              <p role="alert" class="text-red-400">Deletion failed. Try again.</p>
            {/if}
          </div>
        </details>
      {/if}

      <button type="button" onclick={reset} class="text-sm text-neutral-400 hover:text-neutral-100">
        ← Write another note
      </button>
    </div>

    {#if deleteState !== 'deleted'}
      <div>
        <QrCode value={created.link} label="QR code of the share link" />
        <p class="mt-2 text-center text-xs text-neutral-500">
          Scanning this reveals the key. Only show it to the recipient.
        </p>
      </div>
    {/if}
  </section>
{/if}
