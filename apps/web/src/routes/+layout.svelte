<script lang="ts">
  import './layout.css';
  import { asset, resolve } from '$app/paths';
  import type { LayoutProps } from './$types';

  let { children }: LayoutProps = $props();
</script>

<svelte:head>
  <link rel="icon" href={asset('favicon.svg')} type="image/svg+xml" />
</svelte:head>

<a
  href="#main"
  class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:rounded focus:bg-neutral-800 focus:px-3 focus:py-2"
>
  Skip to content
</a>

<div class="mx-auto flex min-h-dvh max-w-5xl flex-col px-4 sm:px-6">
  <header class="flex items-center justify-between py-6">
    <a
      href={resolve('/')}
      class="flex items-center gap-2 font-semibold tracking-tight text-neutral-100"
    >
      <img src={asset('favicon.svg')} alt="" class="size-7" />
      OpSec AIO
    </a>
    <nav aria-label="Primary" class="flex gap-5 text-sm text-neutral-400">
      <a href={resolve('/chat')} class="hover:text-neutral-100">Chat</a>
      <a href={resolve('/drop')} class="hover:text-neutral-100">Drop</a>
      <a href={resolve('/burn')} class="hover:text-neutral-100">Burn</a>
      <a href={resolve('/selftest')} class="hover:text-neutral-100">Self-test</a>
    </nav>
  </header>

  <main id="main" class="flex-1 pb-16">
    {@render children()}
  </main>

  <footer class="border-t border-neutral-800 py-6 text-xs text-neutral-500">
    Everything is encrypted in your browser. The server stores ciphertext it cannot read. No
    analytics, no third-party requests.
    <!-- AGPL-3.0 §13: users interacting over a network must be offered the source. -->
    <a
      href="https://github.com/jagboy88/OPSEC-AIO"
      rel="noopener noreferrer"
      class="ml-1 underline hover:text-neutral-300">Source code (AGPL-3.0)</a
    >
  </footer>
</div>
