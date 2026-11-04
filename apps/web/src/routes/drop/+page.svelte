<script lang="ts">
  import { buildShareLink, wipe } from '@opsec-aio/crypto';
  import {
    DROP_DEFAULT_TTL_SECONDS,
    DROP_EXPIRY_OPTIONS_SECONDS,
    DROP_MAX_BYTES,
    DROP_MAX_DOWNLOAD_OPTIONS,
  } from '@opsec-aio/types';
  import { ApiError, api } from '#lib/api.js';
  import CopyField from '#lib/components/CopyField.svelte';
  import Countdown from '#lib/components/Countdown.svelte';
  import QrCode from '#lib/components/QrCode.svelte';
  import WhoCanRead from '#lib/components/WhoCanRead.svelte';
  import { uploadFile } from '#lib/drop.js';
  import { formatBytes, pluralize } from '#lib/format.js';

  const EXPIRY_LABELS: Record<number, string> = {
    3600: '1 hour',
    21600: '6 hours',
    43200: '12 hours',
    86400: '24 hours',
  };

  let file = $state<File | null>(null);
  let expiresIn = $state<number>(DROP_DEFAULT_TTL_SECONDS);
  let maxDownloads = $state<string>('unlimited');
  let usePassword = $state(false);
  let password = $state('');
  let dragging = $state(false);

  let phase = $state<'pick' | 'uploading' | 'done'>('pick');
  let progress = $state(0);
  let error = $state('');
  let controller: AbortController | null = null;
  let started: { id: string; uploadToken: string } | null = null;

  interface Created {
    id: string;
    name: string;
    size: number;
    link: string;
    deleteLink: string;
    deletionToken: string;
    expiresAt: string;
    maxDownloads: number | null;
    passwordProtected: boolean;
  }
  let created = $state<Created | null>(null);
  let deleteState = $state<'idle' | 'confirm' | 'deleting' | 'deleted' | 'failed'>('idle');

  const tooBig = $derived(file !== null && file.size > DROP_MAX_BYTES);
  const canUpload = $derived(
    phase === 'pick' && file !== null && !tooBig && (!usePassword || password.length > 0),
  );

  function pick(f: File | undefined | null) {
    if (!f) return;
    file = f;
    error = '';
  }

  async function start(e: SubmitEvent) {
    e.preventDefault();
    if (!canUpload || !file) return;
    phase = 'uploading';
    progress = 0;
    error = '';
    controller = new AbortController();
    started = null;
    const limit = maxDownloads === 'unlimited' ? null : Number(maxDownloads);
    try {
      // Let the progress UI paint before Argon2id (if a password is set) blocks.
      await new Promise((r) => setTimeout(r, 30));
      const res = await uploadFile(file, {
        expiresIn,
        maxDownloads: limit,
        ...(usePassword ? { password } : {}),
        signal: controller.signal,
        onStarted: (id, uploadToken) => (started = { id, uploadToken }),
        onProgress: (done, total) => (progress = done / total),
      });
      const flags = usePassword ? ['p'] : [];
      created = {
        id: res.id,
        name: file.name,
        size: file.size,
        link: buildShareLink(location.origin, 'd', res.id, res.linkKey, flags),
        deleteLink: `${location.origin}/d/${res.id}#del.${res.deletionToken}`,
        deletionToken: res.deletionToken,
        expiresAt: res.expiresAt,
        maxDownloads: limit,
        passwordProtected: usePassword,
      };
      wipe(res.linkKey);
      password = '';
      file = null;
      phase = 'done';
    } catch (err) {
      const aborted = err instanceof DOMException && err.name === 'AbortError';
      await abortServerSide();
      phase = 'pick';
      error = aborted
        ? 'Upload cancelled. Nothing was kept on the server.'
        : err instanceof ApiError && err.code === 'storage_full'
          ? 'The server is out of space for new files right now. Try again later or send a smaller file.'
          : err instanceof ApiError && err.code === 'rate_limited'
            ? 'Too many uploads from this connection. Try again later.'
            : 'The upload failed. Nothing usable was left on the server. Please try again.';
    } finally {
      controller = null;
    }
  }

  async function abortServerSide() {
    if (!started) return;
    const s = started;
    started = null;
    await api.deleteDrop(s.id, { upload_token: s.uploadToken }).catch(() => {});
  }

  function cancel() {
    controller?.abort();
  }

  async function deleteNow() {
    if (!created) return;
    deleteState = 'deleting';
    try {
      await api.deleteDrop(created.id, { deletion_token: created.deletionToken });
      deleteState = 'deleted';
    } catch (err) {
      deleteState = err instanceof ApiError && err.status === 404 ? 'deleted' : 'failed';
    }
  }

  function reset() {
    created = null;
    phase = 'pick';
    deleteState = 'idle';
    usePassword = false;
  }

  const field = 'w-full rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm';
</script>

<svelte:head><title>Drop · OpSec AIO</title></svelte:head>

<h1 class="mt-6 text-2xl font-semibold text-neutral-50">Drop a file</h1>
<p class="mt-2 max-w-2xl text-sm text-neutral-400">
  The file is encrypted in this browser before upload and deleted from the server within 24 hours,
  no exceptions.
</p>

{#if phase !== 'done' || !created}
  <form class="mt-6 grid gap-6 lg:grid-cols-[1fr_20rem]" onsubmit={start}>
    <div>
      <label
        for="file"
        class={[
          'flex min-h-56 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center',
          dragging ? 'border-emerald-400 bg-emerald-500/5' : 'border-neutral-700 bg-neutral-900',
          phase === 'uploading' && 'pointer-events-none opacity-60',
        ]}
        ondragover={(e) => {
          e.preventDefault();
          dragging = true;
        }}
        ondragleave={() => (dragging = false)}
        ondrop={(e) => {
          e.preventDefault();
          dragging = false;
          pick(e.dataTransfer?.files[0]);
        }}
      >
        {#if file}
          <span class="font-medium break-all text-neutral-100" data-testid="picked-name"
            >{file.name}</span
          >
          <span class={['mt-1 text-sm', tooBig ? 'text-red-400' : 'text-neutral-400']}>
            {formatBytes(file.size)}{tooBig ? ` (max ${formatBytes(DROP_MAX_BYTES)})` : ''}
          </span>
          <span class="mt-3 text-xs text-neutral-500">Tap to choose a different file</span>
        {:else}
          <span class="font-medium text-neutral-100">Choose a file</span>
          <span class="mt-1 text-sm text-neutral-400"
            >or drag it here · up to {formatBytes(DROP_MAX_BYTES)}</span
          >
        {/if}
        <input
          id="file"
          type="file"
          class="sr-only"
          disabled={phase === 'uploading'}
          onchange={(e) => pick(e.currentTarget.files?.[0])}
        />
      </label>

      {#if phase === 'uploading'}
        <div class="mt-4" role="status" aria-live="polite">
          <progress
            class="progress-bar"
            value={Math.round(progress * 1000)}
            max="1000"
            aria-label="Upload progress"
          ></progress>
          <p class="mt-2 text-sm text-neutral-400">
            {progress === 0
              ? 'Encrypting…'
              : `Encrypted and uploaded ${Math.floor(progress * 100)}%`}
          </p>
        </div>
      {/if}
    </div>

    <div class="space-y-5">
      <div>
        <label for="expiry" class="mb-1 block text-sm font-medium text-neutral-200"
          >Delete after</label
        >
        <select id="expiry" bind:value={expiresIn} class={field} disabled={phase === 'uploading'}>
          {#each DROP_EXPIRY_OPTIONS_SECONDS as s (s)}
            <option value={s}>{EXPIRY_LABELS[s]}</option>
          {/each}
        </select>
      </div>

      <div>
        <label for="downloads" class="mb-1 block text-sm font-medium text-neutral-200"
          >Downloads allowed</label
        >
        <select
          id="downloads"
          bind:value={maxDownloads}
          class={field}
          disabled={phase === 'uploading'}
        >
          {#each DROP_MAX_DOWNLOAD_OPTIONS as n (n)}
            <option value={n === null ? 'unlimited' : String(n)}
              >{n === null ? 'Unlimited (until it expires)' : pluralize(n, 'download')}</option
            >
          {/each}
        </select>
      </div>

      <div>
        <label class="flex items-center gap-2 text-sm text-neutral-200">
          <input
            type="checkbox"
            bind:checked={usePassword}
            disabled={phase === 'uploading'}
            class="size-4 accent-emerald-500"
          />
          Also require a password
        </label>
        {#if usePassword}
          <input
            type="password"
            bind:value={password}
            autocomplete="new-password"
            aria-label="Password"
            placeholder="Password"
            disabled={phase === 'uploading'}
            class="mt-2 {field}"
          />
          <p class="mt-1 text-xs text-neutral-500">
            Send the password through a different channel than the link.
          </p>
        {/if}
      </div>

      {#if phase === 'uploading'}
        <button
          type="button"
          onclick={cancel}
          class="w-full rounded-lg bg-neutral-800 px-4 py-2.5 font-medium hover:bg-neutral-700"
          >Cancel upload</button
        >
      {:else}
        <button
          type="submit"
          disabled={!canUpload}
          class="w-full rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
          >Encrypt & upload</button
        >
      {/if}
      {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
    </div>
  </form>
{:else}
  <section class="mt-6 grid gap-6 lg:grid-cols-[1fr_16rem]" aria-labelledby="ready-heading">
    <div class="space-y-5">
      <h2 id="ready-heading" class="text-lg font-semibold text-emerald-400">Your file is ready</h2>
      <p class="text-sm text-neutral-300">
        <span class="font-medium break-all text-neutral-100">{created.name}</span>
        · {formatBytes(created.size)}
      </p>

      {#if deleteState === 'deleted'}
        <p class="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-sm" role="status">
          The file has been deleted. The link no longer works.
        </p>
      {:else}
        <CopyField value={created.link} label="Share this link" testid="share-link" />
        <p class="text-sm text-neutral-400">
          Deleted in <Countdown until={created.expiresAt} />{created.maxDownloads === null
            ? '.'
            : `, or after ${pluralize(created.maxDownloads, 'download')}.`}
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
            detail:
              'until it expires. The key is the part after #, which never reaches the server.',
          },
          {
            who: 'OpSec AIO servers',
            can: false,
            detail:
              'they store encrypted chunks, a rough size bucket, the expiry time and the download count. Not the file name, type, exact size or contents.',
          },
          {
            who: 'Anyone after the deadline',
            can: false,
            detail: 'the encrypted file is deleted from the server within 24 hours, no exceptions.',
          },
        ]}
      />

      {#if deleteState !== 'deleted'}
        <details class="rounded-xl border border-neutral-800 p-4 text-sm">
          <summary class="cursor-pointer font-medium text-neutral-200">Delete it early</summary>
          <div class="mt-3 space-y-3">
            <p class="text-neutral-400">
              Save this deletion link if you might want to remove the file after leaving this page.
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
        ← Send another file
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
