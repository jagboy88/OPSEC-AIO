<script lang="ts">
  interface Row {
    who: string;
    can: boolean;
    detail: string;
  }
  let { rows, title = 'Who can read this?' }: { rows: Row[]; title?: string } = $props();
</script>

<section
  aria-labelledby="who-can-read"
  class="rounded-xl border border-neutral-800 bg-neutral-900/50 p-5"
>
  <h2 id="who-can-read" class="mb-3 text-sm font-semibold text-neutral-100">{title}</h2>
  <ul class="space-y-2 text-sm">
    {#each rows as row (row.who)}
      <li class="flex gap-3">
        <span
          class={[
            'mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-xs font-bold',
            row.can ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400',
          ]}
          aria-hidden="true">{row.can ? '✓' : '✕'}</span
        >
        <span>
          <span class="font-medium text-neutral-100">{row.who}</span>
          <span class="sr-only">{row.can ? ' can read it.' : ' cannot read it.'}</span>
          <span class="text-neutral-400"> — {row.detail}</span>
        </span>
      </li>
    {/each}
  </ul>
</section>
