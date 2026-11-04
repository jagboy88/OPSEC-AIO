<script lang="ts">
  import {
    ChatInputError,
    ChatServerError,
    UsernameTakenError,
    generateUsername,
  } from '@opsec-aio/chat';
  import { DecryptionError } from '@opsec-aio/crypto';
  import { chat } from './state.svelte.js';

  const MIN_PASSPHRASE = 10;
  const USERNAME_INPUT_PATTERN = '[a-z0-9_]{3,32}';

  let username = $state(generateUsername());
  let passphrase = $state('');
  let confirm = $state('');
  let busy = $state('');
  let error = $state('');
  let confirmForget = $state(false);

  const paint = () => new Promise((r) => setTimeout(r, 30));

  async function create(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (passphrase.length < MIN_PASSPHRASE) {
      error = `Use at least ${MIN_PASSPHRASE} characters for your passphrase.`;
      return;
    }
    if (passphrase !== confirm) {
      error = 'The passphrases do not match.';
      return;
    }
    busy = 'Generating keys and strengthening your passphrase…';
    await paint();
    try {
      await chat.createAccount(username.trim().toLowerCase(), passphrase);
      passphrase = confirm = '';
    } catch (err) {
      error =
        err instanceof UsernameTakenError
          ? 'That username is taken. Try another, or generate one.'
          : err instanceof ChatInputError
            ? err.message
            : err instanceof ChatServerError && err.code === 'rate_limited'
              ? 'Too many sign-ups from this connection. Try again later.'
              : 'Could not create the account. Check your connection and try again.';
    } finally {
      busy = '';
    }
  }

  async function unlock(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = 'Unlocking…';
    await paint();
    try {
      await chat.unlock(passphrase);
      passphrase = '';
    } catch (err) {
      error =
        err instanceof DecryptionError
          ? 'Wrong passphrase.'
          : 'Could not connect to the server. Check your connection and try again.';
    } finally {
      busy = '';
    }
  }

  async function importFile(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    error = '';
    try {
      await chat.importKeystore(f);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Import failed.';
    }
  }

  const input =
    'w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-neutral-100';
  const primary =
    'w-full rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-neutral-950 hover:bg-emerald-400 disabled:opacity-40';
</script>

<div class="mx-auto mt-6 max-w-md">
  {#if chat.phase === 'no-account'}
    <form
      class="space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-6"
      onsubmit={create}
    >
      <h2 class="text-lg font-semibold text-neutral-50">Create a chat account</h2>
      <p class="text-sm text-neutral-400">
        No email, no phone number. Your keys are generated and kept on this device.
      </p>
      <div>
        <label for="username" class="mb-1 block text-sm font-medium text-neutral-200"
          >Username</label
        >
        <div class="flex gap-2">
          <input
            id="username"
            bind:value={username}
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            class={input}
            pattern={USERNAME_INPUT_PATTERN}
            required
          />
          <button
            type="button"
            class="shrink-0 rounded-lg bg-neutral-800 px-3 text-sm hover:bg-neutral-700"
            onclick={() => (username = generateUsername())}>Random</button
          >
        </div>
        <p class="mt-1 text-xs text-neutral-500">3–32 characters: a–z, 0–9 and _.</p>
      </div>
      <div>
        <label for="pass" class="mb-1 block text-sm font-medium text-neutral-200">Passphrase</label>
        <input
          id="pass"
          type="password"
          bind:value={passphrase}
          autocomplete="new-password"
          class={input}
          required
        />
      </div>
      <div>
        <label for="pass2" class="mb-1 block text-sm font-medium text-neutral-200"
          >Repeat passphrase</label
        >
        <input
          id="pass2"
          type="password"
          bind:value={confirm}
          autocomplete="new-password"
          class={input}
          required
        />
      </div>
      <p class="rounded-lg bg-amber-500/10 p-3 text-xs text-amber-200">
        The passphrase unlocks your keys on this device and never leaves it. It cannot be reset: if
        you forget it, this account is gone.
      </p>
      <button type="submit" class={primary} disabled={!!busy}>{busy || 'Create account'}</button>
      {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
      <div class="border-t border-neutral-800 pt-4 text-sm text-neutral-400">
        <label class="cursor-pointer hover:text-neutral-200">
          Moving an existing account here? <span class="underline">Import a keystore file</span>
          <input
            type="file"
            class="sr-only"
            accept=".opsec,application/octet-stream"
            onchange={importFile}
          />
        </label>
      </div>
    </form>
  {:else if chat.phase === 'locked'}
    <form
      class="space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-6"
      onsubmit={unlock}
    >
      <h2 class="text-lg font-semibold text-neutral-50">Unlock chat</h2>
      <p class="text-sm text-neutral-400">Your messages and keys on this device are encrypted.</p>
      <div>
        <label for="unlock" class="mb-1 block text-sm font-medium text-neutral-200"
          >Passphrase</label
        >
        <input
          id="unlock"
          type="password"
          bind:value={passphrase}
          autocomplete="current-password"
          class={input}
          required
        />
      </div>
      <button type="submit" class={primary} disabled={!!busy || !passphrase}
        >{busy || 'Unlock'}</button
      >
      {#if error}<p role="alert" class="text-sm text-red-400">{error}</p>{/if}
      <div class="border-t border-neutral-800 pt-4 text-sm">
        {#if confirmForget}
          <p class="text-neutral-300">
            Remove the account from this browser? Without a keystore export, it can't be recovered.
          </p>
          <div class="mt-2 flex gap-2">
            <button
              type="button"
              class="rounded-lg bg-red-500 px-3 py-1.5 font-medium text-neutral-950"
              onclick={() => chat.forgetDevice()}>Remove from this device</button
            >
            <button
              type="button"
              class="rounded-lg bg-neutral-800 px-3 py-1.5"
              onclick={() => (confirmForget = false)}>Cancel</button
            >
          </div>
        {:else}
          <button
            type="button"
            class="text-neutral-400 hover:text-neutral-200"
            onclick={() => (confirmForget = true)}>Forgot the passphrase?</button
          >
        {/if}
      </div>
    </form>
  {/if}
</div>
