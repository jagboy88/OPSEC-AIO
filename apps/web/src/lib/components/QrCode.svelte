<script lang="ts">
  import { encode } from 'uqr';

  let { value, label }: { value: string; label: string } = $props();

  // Rendered as a single SVG path built from the module matrix — no innerHTML,
  // no canvas, no data: URLs, so it works under the strict CSP.
  const qr = $derived(encode(value, { ecc: 'M', border: 2 }));
  const path = $derived.by(() => {
    let d = '';
    qr.data.forEach((row, y) =>
      row.forEach((dark, x) => {
        if (dark) d += `M${x} ${y}h1v1h-1z`;
      }),
    );
    return d;
  });
</script>

<svg
  viewBox="0 0 {qr.size} {qr.size}"
  role="img"
  aria-label={label}
  class="aspect-square w-full rounded-lg bg-white"
  shape-rendering="crispEdges"
>
  <path d={path} fill="#000" />
</svg>
