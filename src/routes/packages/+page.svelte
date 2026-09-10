<script lang="ts">
  import { navigating } from '$app/stores';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PackageRow from '$lib/components/PackageRow.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { Release } from '$lib/model';
  import type { PageData } from './$types';

  export let data: PageData;

  $: packages = (Array.isArray(data?.packages) ? data.packages : Array.isArray(data?.releases) ? data.releases : []) as Release[];

  let query = data?.query || '';

  let channel = data?.channel || 'stable';

  let surface = data?.surface || '';

  let architecture = data?.architecture || '';

  $: if (data) {
    query = data.query || '';
    channel = data.channel || 'stable';
    surface = data.surface || '';
    architecture = data.architecture || '';
  }

  $: loading = Boolean($navigating);
  $: user = data?.user || null;
  $: role = data?.role || 'public';

  function nextPageHref() {
    const params = new URLSearchParams();

    if (query) params.set('q', query);

    if (channel) params.set('channel', channel);

    if (surface) params.set('surface', surface);

    if (architecture) params.set('architecture', architecture);

    if (data.nextCursor) params.set('cursor', data.nextCursor);

    return `/packages?${params}`;
  }
</script>

<svelte:head>
  <title>Packages · omapkg</title>
  <meta name="description" content="Browse reviewed Omarchy package releases." />
</svelte:head>

<PublicNav {user} {role} packages={packages} />

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="packages-title">
    <div class="section__head">
      <div>
        <h1 id="packages-title">Packages</h1>
      </div>
      <p>Search releases by source, channel, or architecture. Each package record includes evidence links.</p>
    </div>

    <form class="filter-bar" method="GET">
      <div class="field">
        <label for="package-search">Package name</label>
        <input id="package-search" name="q" type="search" bind:value={query} placeholder="e.g. package-name" />
      </div>
      <div class="field">
        <label for="channel">Channel</label>
        <select id="channel" name="channel" bind:value={channel}>
          <option value="all">All channels</option>
          <option value="stable">Stable</option>
          <option value="dev">Dev</option>
          <option value="withdrawn">Withdrawn</option>
        </select>
      </div>
      <div class="field">
        <label for="surface">Surface</label>
        <select id="surface" name="surface" bind:value={surface}>
          <option value="">All surfaces</option>
          <option value="binary">Surface A · binary</option>
          <option value="recipe">Surface B · recipe</option>
        </select>
      </div>
      <div class="field">
        <label for="architecture">Architecture</label>
        <select id="architecture" name="architecture" bind:value={architecture}>
          <option value="">All architectures</option>
          <option value="x86_64">x86_64</option>
          <option value="aarch64">aarch64</option>
        </select>
      </div>
      <button class="button button--primary" type="submit"><Icon name="search" size={15} />Filter</button>
    </form>

    {#if data.systemVersion}<p class="field__hint">Published system context: Omarchy {data.systemVersion}. Package compatibility still requires an exact release record.</p>{/if}
    {#if loading}<p class="catalog-loading" role="status" aria-live="polite">Loading published package records…</p>{/if}

    {#if packages.length}
      <div class="section__head section__head--results">
        <p>Showing {packages.length} published release record{packages.length === 1 ? '' : 's'}{data.hasNext ? ' on this page' : ''}.</p>
        <a href="/request">Request a package<Icon name="arrow" size={14} /></a>
      </div>
      <div class="package-list" aria-busy={loading}>
        {#each packages as release}
          <PackageRow {release} />
        {/each}
      </div>
      {#if data.nextCursor}<nav class="catalog-pagination" aria-label="Package catalogue pages"><a class="button" href={nextPageHref()}>Next page<Icon name="arrow" size={14} /></a></nav>{/if}
    {:else}
      <EmptyState
        title={query || channel !== 'stable' || surface || architecture ? 'No releases match those filters.' : 'No public releases yet.'}
        description={query || channel !== 'stable' || surface || architecture ? 'Change a filter or request a package that is not in the catalogue yet.' : 'A release appears here after its generated recipe is reviewed and its channel state is recorded.'}
        actionLabel={query || channel !== 'stable' || surface || architecture ? 'Clear filters' : 'Request a package'}
        actionHref={query || channel !== 'stable' || surface || architecture ? '/packages' : '/request'}
        icon={query || channel !== 'stable' || surface || architecture ? 'search' : 'package'}
      />
    {/if}
  </section>

  <footer class="site-footer">
    <p>omapkg · package records</p>
    <nav class="site-footer__links" aria-label="Footer navigation"><a href="/">Home</a><a href="/docs">Docs</a><a href="/request">Request</a></nav>
  </footer>
</main>

<style>
  .catalog-loading { color: var(--color-text-muted); font-family: var(--font-body); margin-block: var(--space-md); }
  .catalog-pagination { display: flex; justify-content: center; margin-top: var(--space-xl); }
</style>
