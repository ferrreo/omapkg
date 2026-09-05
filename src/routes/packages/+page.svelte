<script lang="ts">
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
  $: filtered = packages.filter((release) => {
    const matchesQuery = !query || release.name.toLowerCase().includes(query.toLowerCase());
    const matchesChannel = !channel || release.channel === channel;
    const matchesSurface = !surface || release.surface === surface;
    const matchesArch = !architecture || release.architecture === architecture;
    return matchesQuery && matchesChannel && matchesSurface && matchesArch;
  });
  $: user = data?.user || null;
  $: role = data?.role || 'public';
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
          <option value="">All channels</option>
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

    {#if packages.length && filtered.length}
      <div class="section__head section__head--results">
        <p>{filtered.length} release{filtered.length === 1 ? '' : 's'} in current view.</p>
        <a href="/request">Request a package<Icon name="arrow" size={14} /></a>
      </div>
      <div class="package-list">
        {#each filtered as release}
          <PackageRow {release} />
        {/each}
      </div>
    {:else if packages.length}
      <EmptyState
        title="No releases match those filters."
        description="Change a filter or request a package that is not in the catalogue yet."
        actionLabel="Clear filters"
        actionHref="/packages"
        icon="search"
      />
    {:else}
      <EmptyState
        title="No public releases yet."
        description="A release appears here after its generated recipe is reviewed and its channel state is recorded."
        actionLabel="Request a package"
        actionHref="/request"
        icon="package"
      />
    {/if}
  </section>

  <footer class="site-footer">
    <p>omapkg · package records</p>
    <nav class="site-footer__links" aria-label="Footer navigation"><a href="/">Home</a><a href="/docs">Docs</a><a href="/request">Request</a></nav>
  </footer>
</main>
