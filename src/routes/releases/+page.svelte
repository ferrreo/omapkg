<script lang="ts">
  import DistributionReleaseCard from '$lib/components/DistributionReleaseCard.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { PageData } from './$types';

  export let data: PageData;
  $: view = data.view;
  $: user = data?.user || null;
  $: role = data?.role || 'public';
  $: contextLabel = view.selectedSystemVersion ? `System release · Omarchy ${view.selectedSystemVersion}` : 'Choose your system';
</script>

<svelte:head>
  <title>System releases and OPR updates · omapkg</title>
  <meta name="description" content="Review published Omarchy system releases, independent OPR package updates, compatibility, checks, changelogs, and recovery evidence." />
</svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="release-title">
    <header class="section__head release-page__head">
      <div><p class="eyebrow">Published release records</p><h1 id="release-title">System releases and OPR updates</h1><p>System versions and independent OPR packages have separate release identities. Select a system version to inspect compatibility; a browser cannot infer your installed system.</p></div>
      <a href="/repository">Repository status<Icon name="arrow" size={14} /></a>
    </header>

    <form class="filter-bar release-page__filters" method="GET" aria-label="Choose release context">
      <div class="field"><label for="system-version">System version</label><input id="system-version" name="systemVersion" value={data.systemVersion} placeholder="4.0.3 or 4.0.3-rc2" inputmode="decimal" aria-describedby="system-version-help" /></div>
      <div class="field"><label for="architecture">Target architecture</label><select id="architecture" name="architecture" value={data.architecture}><option value="">Both primary targets</option><option value="x86_64">Intel/AMD · x86_64</option><option value="aarch64">ARM64 · aarch64</option></select></div>
      <button class="button button--primary" type="submit"><Icon name="search" size={15} />View compatibility</button>
      <p id="system-version-help" class="field__hint">This selection stays in the URL and is a compatibility preview. It does not change a machine.</p>
    </form>

    <aside class="release-context" aria-label="Selected release context">
      <div><span class="eyebrow">Compatibility context</span><strong>{contextLabel}</strong></div>
      <p>{view.selectedArchitecture ? `Target: ${view.selectedArchitecture}` : 'Target: both required architectures'}. No package inventory or telemetry is uploaded.</p>
    </aside>

    {#if view.notice}<p class="notice-bar" role="status"><Icon name="activity" size={15} />{view.notice}</p>{/if}

    <section class="release-lane" aria-labelledby="system-lane-title">
      <div class="release-lane__head"><div><p class="eyebrow">Lane 1 · edge → rc → stable</p><h2 id="system-lane-title">System releases</h2><p>Core, extra, and the pinned system set move together under one immutable system version.</p></div><span class="tag tag--accent">Omarchy version</span></div>
      {#if view.systemReleases.length}{#each view.systemReleases as release}<DistributionReleaseCard {release} />{/each}{:else}<EmptyState title="No system release manifest in this projection." description="Published system versions will appear here with their exact candidate, target checks, changelog approval, compatibility lock, and recovery predecessor. Existing OPR records do not imply a system release." icon="archive" />{/if}
    </section>

    <section class="release-lane" aria-labelledby="opr-lane-title">
      <div class="release-lane__head"><div><p class="eyebrow">Lane 2 · review → quarantine → stable</p><h2 id="opr-lane-title">Independent OPR updates</h2><p>Each package keeps its own version and can ship without a new system version when its compatibility snapshot is recorded.</p></div><span class="tag tag--positive">Package versions</span></div>
      {#if view.oprReleases.length}<div class="release-list">{#each view.oprReleases as release}<DistributionReleaseCard {release} />{/each}</div>{:else}<EmptyState title="No published OPR release in this view." description="A package appears after its immutable generation and repository projection are activated. Candidate and testing records stay in the maintainer workbench. Missing coverage stays visible as a request or blocker; it does not fall back to AUR or ALARM." actionLabel="Browse packages" actionHref="/packages" icon="package" />{/if}
    </section>

    <section class="release-lane release-lane--transaction" aria-labelledby="transaction-title">
      <div class="release-lane__head"><div><p class="eyebrow">Client transaction</p><h2 id="transaction-title">Resolved compatibility</h2><p>A local client should resolve one system manifest plus a compatible OPR snapshot before changing a machine. The web view cannot inspect your installed package set.</p></div><span class="tag">Preview only</span></div>
      {#if view.transactions.length}{#each view.transactions as release}<DistributionReleaseCard {release} />{/each}{:else}<p class="release-empty-copy">No resolved transaction was supplied by a trusted local client. Use the selected context to inspect published evidence, then follow the reviewed install steps from the package or system record.</p>{/if}
    </section>

    <section class="release-help" aria-labelledby="release-help-title"><h2 id="release-help-title">What the records mean</h2><dl><div><dt>Built</dt><dd>Worker output exists. It may still be missing review, target tests, changelog approval, or publication.</dd></div><div><dt>Published</dt><dd>Immutable repository and release records are active for the stated targets. This does not claim software is harmless.</dd></div><div><dt>Blocked</dt><dd>A named check, dependency, architecture result, or human decision is missing. No external repository is suggested as a workaround.</dd></div></dl></section>
  </section>

  <footer class="site-footer"><p>omapkg · versioned system and independent OPR release records</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/packages">Packages</a><a href="/repository">Repository</a><a href="/docs">Docs</a></nav></footer>
</main>

<style>
  .release-page__head { align-items: end; }
  .release-page__head > div { display: grid; gap: var(--space-sm); }
  .release-page__head a { align-items: center; display: inline-flex; gap: var(--space-xs); white-space: nowrap; }
  .release-page__filters { margin-bottom: var(--space-lg); }
  .release-page__filters .field { flex: 1 1 14rem; }
  .release-page__filters .field:nth-child(2), .release-page__filters .field:nth-child(3) { flex-basis: 11rem; }
  .release-context { align-items: baseline; background: var(--color-surface); border-left: .2rem solid var(--color-accent); display: flex; flex-wrap: wrap; gap: var(--space-lg); justify-content: space-between; margin-bottom: var(--space-xl); padding: var(--space-md) var(--space-lg); }
  .release-context > div { display: grid; gap: var(--space-2xs); min-width: 0; }
  .release-context strong { color: var(--color-text-strong); overflow-wrap: anywhere; }
  .release-context p { color: var(--color-text-muted); font-size: var(--text-sm); }
  .release-lane { display: grid; gap: var(--space-lg); margin-top: var(--space-3xl); min-width: 0; }
  .release-lane__head { align-items: start; border-bottom: var(--border-width) solid var(--color-rule); display: flex; flex-wrap: wrap; gap: var(--space-lg); justify-content: space-between; padding-bottom: var(--space-md); }
  .release-lane__head > div { display: grid; gap: var(--space-xs); min-width: 0; }
  .release-lane__head p:not(.eyebrow) { color: var(--color-text-muted); font-family: var(--font-body); font-size: var(--text-sm); }
  .release-list { display: grid; gap: var(--space-lg); min-width: 0; }
  .release-lane--transaction { background: var(--color-canvas-deep); padding: var(--space-lg); }
  .release-empty-copy { color: var(--color-text); font-family: var(--font-body); max-width: 72ch; }
  .release-help { border-top: var(--border-width) solid var(--color-rule); display: grid; gap: var(--space-lg); margin-top: var(--space-3xl); padding-top: var(--space-lg); }
  .release-help dl { display: grid; gap: var(--space-md); }
  .release-help dl div { border-bottom: var(--border-width) solid var(--color-rule-soft); display: grid; gap: var(--space-xs); grid-template-columns: minmax(8rem, .4fr) minmax(0, 1.6fr); padding-bottom: var(--space-md); }
  .release-help dt { color: var(--color-accent-strong); text-transform: uppercase; }
  .release-help dd { color: var(--color-text); font-family: var(--font-body); margin: 0; }
  @media (max-width: 39.99rem) { .release-help dl div { grid-template-columns: 1fr; } }
</style>
