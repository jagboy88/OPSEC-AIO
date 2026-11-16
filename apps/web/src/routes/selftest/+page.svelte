<script lang="ts">
  import { runSelfTest, webAssemblyAvailable, type SelfTestResult } from '@opsec-aio/crypto';
  import WasmNotice from '#lib/components/WasmNotice.svelte';

  let results = $state<SelfTestResult[] | null>(null);
  let failed = $state(false);

  $effect(() => {
    runSelfTest().then(
      (r) => (results = r),
      () => (failed = true),
    );
  });

  const allOk = $derived(results !== null && results.every((r) => r.ok));
</script>

<h1 class="mt-6 text-2xl font-semibold text-neutral-50">Crypto self-test</h1>
<p class="mt-2 max-w-2xl text-sm text-neutral-400">
  These known-answer tests run locally in your browser. They check that the encryption code on this
  device produces exactly the outputs published in the relevant standards.
</p>

<div class="mt-6 rounded-xl border border-neutral-800 bg-neutral-900 p-5" aria-live="polite">
  {#if failed && !webAssemblyAvailable()}
    <p class="mb-3 font-medium text-red-400" data-testid="selftest-status">
      Crypto failed to load in this browser.
    </p>
    <WasmNotice />
  {:else if failed}
    <p class="font-medium text-red-400" data-testid="selftest-status">
      Crypto failed to load in this browser.
    </p>
  {:else if results === null}
    <p class="text-neutral-400" data-testid="selftest-status">Running…</p>
  {:else}
    <p
      class={['mb-4 font-medium', allOk ? 'text-emerald-400' : 'text-red-400']}
      data-testid="selftest-status"
    >
      {allOk ? 'All checks passed.' : 'Some checks FAILED. Do not use this device for secrets.'}
    </p>
    <ul class="space-y-1.5 font-mono text-sm">
      {#each results as r (r.name)}
        <li class="flex gap-3">
          <span class={r.ok ? 'text-emerald-400' : 'text-red-400'}>{r.ok ? 'PASS' : 'FAIL'}</span>
          <span class="text-neutral-300">{r.name}</span>
        </li>
      {/each}
    </ul>
  {/if}
</div>
