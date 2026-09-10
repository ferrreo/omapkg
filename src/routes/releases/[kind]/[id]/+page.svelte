<script lang="ts">
  import DistributionReleaseCard from '$lib/components/DistributionReleaseCard.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { PageData } from './$types';

  export let data: PageData;
  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head>
  <title>{data.view.identity.version ?? data.view.identity.generation ?? 'Release'} · release · omapkg</title>
  <meta name="description" content="Immutable omapkg release record with compatibility, target evidence, changelog, and recovery details." />
</svelte:head>

<PublicNav {user} {role} />
<main class="public-main"><section class="section site-width--narrow" aria-labelledby="release-record-title">
  <p><a href="/releases">← All release records</a></p>
  <header class="section__head"><div><p class="eyebrow">Immutable release record</p><h1 id="release-record-title">{data.view.identity.version ?? data.view.identity.generation ?? 'Version not recorded'}</h1><p>Exact manifest sequence {data.view.sequence}. Compatibility and recovery evidence below describe this record only.</p></div></header>
  <DistributionReleaseCard release={data.view} />
  <p class="release-record__note">A public release record documents published bytes and review evidence. It does not prove software harmless, infer installed state, or start a package-manager transaction.</p>
</section></main>

<style>
  .release-record__note { border-top: var(--border-width) solid var(--color-rule); color: var(--color-text-muted); font-family: var(--font-body); margin-top: var(--space-xl); padding-top: var(--space-lg); }
</style>
