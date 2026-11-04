<script lang="ts">
  import { formatRemaining } from '#lib/format.js';

  let { until }: { until: string } = $props();

  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(t);
  });

  const target = $derived(Date.parse(until));
</script>

<time datetime={until} title={new Date(target).toLocaleString()}
  >{formatRemaining(target - now)}</time
>
