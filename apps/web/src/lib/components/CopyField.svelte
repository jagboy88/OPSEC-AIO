<script lang="ts">
  let { value, label, testid }: { value: string; label: string; testid?: string } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const id = $props.id();

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 2000);
    } catch {
      // Clipboard blocked: select the text so the user can copy manually.
      (document.getElementById(id) as HTMLInputElement | null)?.select();
    }
  }

  $effect(() => () => clearTimeout(timer));
</script>

<div>
  <label for={id} class="mb-1 block text-xs font-medium text-neutral-400">{label}</label>
  <div class="flex gap-2">
    <input
      {id}
      readonly
      {value}
      data-testid={testid}
      class="min-w-0 flex-1 rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm text-neutral-100"
      onfocus={(e) => e.currentTarget.select()}
    />
    <button
      type="button"
      onclick={copy}
      class="shrink-0 rounded-lg bg-neutral-800 px-3 py-2 text-sm font-medium text-neutral-100 hover:bg-neutral-700"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  </div>
  <span class="sr-only" aria-live="polite">{copied ? 'Copied to clipboard' : ''}</span>
</div>
