<script lang="ts">
  import { resolve } from '$app/paths';
  /**
   * Shown site-wide when the browser has WebAssembly turned off. All of
   * OpSec AIO's encryption runs on it (libsodium), so nothing can work until
   * it is allowed for this site. Common culprits are privacy hardening
   * features, so explain how to make a per-site exception.
   */
  let { compact = false }: { compact?: boolean } = $props();
</script>

<div
  role="alert"
  class="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-100"
  data-testid="wasm-notice"
>
  <p class="font-semibold text-amber-200">
    This browser has WebAssembly turned off, so encryption can't run here.
  </p>
  {#if !compact}
    <p class="mt-1 text-amber-100/90">
      Chat, Drop and Burn encrypt everything on your device using WebAssembly. It is usually
      switched off by a privacy-hardening setting. You can allow it for just this site:
    </p>
    <ul class="mt-2 list-disc space-y-1 pl-5 text-amber-100/90">
      <li>
        <strong>iPhone / iPad (Lockdown Mode):</strong> in Safari tap <em>aA</em> →
        <em>Website Settings</em>
        → turn off <em>Lockdown Mode</em> for this site.
      </li>
      <li>
        <strong>GrapheneOS (Vanadium):</strong> tap the lock icon → <em>Permissions</em> /
        <em>Site settings</em>
        → allow <em>JavaScript JIT</em> for this site.
      </li>
      <li>
        <strong>Tor Browser:</strong> shield icon → set the security level to <em>Standard</em>.
      </li>
      <li>
        <strong>Firefox / Brave with hardened settings:</strong> make sure
        <code>javascript.options.wasm</code> is on (Firefox) or WebAssembly isn't blocked for this site.
      </li>
    </ul>
    <p class="mt-2 text-amber-100/70">
      Then reload the page. The <a href={resolve('/selftest')} class="underline">self-test</a> shows whether
      it works.
    </p>
  {/if}
</div>
