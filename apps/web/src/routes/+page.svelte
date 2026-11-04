<script lang="ts">
  import WhoCanRead from '#lib/components/WhoCanRead.svelte';

  const modules = [
    {
      name: 'Chat',
      href: '/chat',
      blurb: 'End-to-end encrypted 1:1 and small-group chat with disappearing messages.',
      detail: 'Signal Protocol · account required',
      status: 'Phase 3',
    },
    {
      name: 'Drop',
      href: '/drop',
      blurb: 'Send an encrypted file with a link. Deleted 24 hours after upload, no exceptions.',
      detail: 'Up to 2 GB · no account',
      status: 'Phase 2',
    },
    {
      name: 'Burn',
      href: '/burn',
      blurb: 'A note that is destroyed the moment it is read.',
      detail: 'Up to 64 KB · no account',
      status: 'Phase 1',
    },
  ];
</script>

<section class="py-10 sm:py-16">
  <h1 class="text-3xl font-semibold tracking-tight text-neutral-50 sm:text-4xl">
    Private by construction.
  </h1>
  <p class="mt-3 max-w-2xl text-neutral-400">
    Chat, file drops and self-destructing notes, encrypted in your browser before anything leaves
    your device. The server never has the keys.
  </p>
</section>

<section aria-label="Modules" class="grid gap-4 sm:grid-cols-3">
  {#each modules as m (m.name)}
    <div
      class="flex flex-col rounded-xl border border-neutral-800 bg-neutral-900 p-5"
      aria-disabled="true"
    >
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold text-neutral-50">{m.name}</h2>
        <span class="rounded-full bg-neutral-800 px-2 py-0.5 text-xs text-neutral-400">
          Coming in {m.status}
        </span>
      </div>
      <p class="mt-2 flex-1 text-sm text-neutral-300">{m.blurb}</p>
      <p class="mt-4 text-xs text-neutral-500">{m.detail}</p>
    </div>
  {/each}
</section>

<div class="mt-8 grid gap-4 md:grid-cols-2">
  <WhoCanRead
    rows={[
      { who: 'You and the people you share with', can: true, detail: 'only holders of the key.' },
      {
        who: 'OpSec AIO servers',
        can: false,
        detail: 'we store ciphertext and the minimum metadata needed to deliver and expire it.',
      },
      { who: 'Our hosting provider', can: false, detail: 'disks hold only encrypted data.' },
      {
        who: 'Anyone with a database leak or court order',
        can: false,
        detail: 'there is nothing readable to hand over.',
      },
    ]}
  />
  <section class="rounded-xl border border-neutral-800 bg-neutral-900/50 p-5 text-sm">
    <h2 class="mb-3 font-semibold text-neutral-100">What this does not protect against</h2>
    <ul class="list-disc space-y-1.5 pl-5 text-neutral-400">
      <li>A compromised device: malware on your phone or computer can read what you read.</li>
      <li>
        A malicious server swapping the app code. Published build hashes reduce this risk but don't
        remove it.
      </li>
      <li>Network-level traffic analysis. Use Tor if who you talk to is itself sensitive.</li>
    </ul>
  </section>
</div>
