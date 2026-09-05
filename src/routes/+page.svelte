<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PackageRow from '$lib/components/PackageRow.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { PageData } from './$types';

  export let data: PageData;

  $: packages = Array.isArray(data?.packages) ? data.packages : [];
  $: user = data?.user || null;
  $: role = data?.role || 'public';
  $: stats = data?.stats || null;

  const workflow = [
    ['01', 'Package request', 'Name, description, license, and upstream URL.'],
    ['02', 'Maintainer approval', 'Area queue review.'],
    ['03', 'Factory', 'An agent generates the PKGBUILD.'],
    ['04', 'Generated review', 'Area and security review the generated inputs.'],
    ['05', 'Build and signing', 'Verified sources, an offline build, separate signing.'],
    ['06', 'Dev channel', 'Quarantine, smoke tests, and feedback.'],
    ['07', 'Stable channel', 'A maintainer promotes a compatible batch.'],
    ['08', 'Distribution', 'Signed packages, recipes, and evidence.']
  ];
</script>

<svelte:head>
  <title>omapkg · inspect before install</title>
  <meta name="description" content="A reviewable package registry for Omarchy and Arch users." />
</svelte:head>

<PublicNav {user} {role} packages={packages} />

<main class="public-main">
  <section class="public-intro" aria-labelledby="home-title">
    <div class="public-intro__copy">
        <span class="eyebrow">omapkg / Arch package index</span>
      <h1 id="home-title">Packages you can inspect</h1>
      <p>omapkg records the request, source checks, generated recipe, build evidence, and signature for each Arch package. The source stays visible. The signing key stays away from workers.</p>
      <div class="action-row">
        <a class="button button--primary" href="/packages">Browse packages<Icon name="arrow" size={14} /></a>
        <a class="button" href="/request">Request a package<Icon name="plus" size={14} /></a>
      </div>
    </div>

    <ol class="workflow" aria-label="Package lifecycle">
      {#each workflow as [index, title, description]}
        <li class="workflow__step">
          <span class="workflow__index">{index}</span>
          <div>
            <strong>{title}</strong>
            <p>{description}</p>
          </div>
        </li>
      {/each}
    </ol>
  </section>

  {#if stats}
    <section class="section section--tight" aria-label="Registry counts">
      <div class="metric-strip">
        <div class="metric"><span class="metric__value">{stats.stable ?? '—'}</span><span class="metric__label">stable releases</span></div>
        <div class="metric"><span class="metric__value">{stats.dev ?? '—'}</span><span class="metric__label">in dev</span></div>
        <div class="metric"><span class="metric__value">{stats.requests ?? '—'}</span><span class="metric__label">open requests</span></div>
      </div>
    </section>
  {/if}

  <section class="section" aria-labelledby="catalog-title">
    <div class="section__head">
      <div>
        <h2 id="catalog-title">Latest releases</h2>
      </div>
      <a href="/packages">View all packages<Icon name="arrow" size={14} /></a>
    </div>

    {#if packages.length}
      <div class="package-list">
        {#each packages.slice(0, 6) as release}
          <PackageRow {release} />
        {/each}
      </div>
    {:else}
      <EmptyState
        title="No packages published yet."
        description="The catalogue will show releases after a reviewed build reaches dev or stable. You can still request a package."
        actionLabel="Request a package"
        actionHref="/request"
        icon="package"
      />
    {/if}
  </section>

  <section class="section" aria-labelledby="surfaces-title">
    <div class="section__head">
      <div>
        <h2 id="surfaces-title">Build records</h2>
      </div>
      <p>Redistributable software becomes a signed binary. For software we cannot redistribute, Surface B keeps vendor bytes at their source and publishes a reviewed recipe with a pinned checksum.</p>
    </div>

    <div class="surface-grid">
      <article class="surface-panel">
        <div class="surface-panel__top"><h3>Surface A · binaries</h3><span class="tag tag--positive"><Icon name="check" size={13} />signed</span></div>
        <p>omapkg hosts packages whose license permits redistribution. Each release points to its source digest, build inputs, attestation, signature, and test evidence.</p>
        <span class="surface-panel__meta">R2 artifact · pacman repository · immutable history</span>
      </article>
      <article class="surface-panel surface-panel--recipe">
        <div class="surface-panel__top"><h3>Surface B · recipes</h3><span class="tag tag--accent"><Icon name="code" size={13} />vendor fetch</span></div>
        <p>Chrome, NVIDIA, Zoom, Spotify, and similar packages keep their bytes at the vendor. omapkg publishes the reviewed recipe and pinned checksum.</p>
        <span class="surface-panel__meta">No proprietary bytes stored by omapkg</span>
      </article>
    </div>
  </section>

  <section class="section" aria-labelledby="promise-title">
      <div class="surface-panel surface-panel--recipe">
      <div class="surface-panel__top"><h2 id="promise-title">Stable channel</h2><Icon name="shield" size={22} /></div>
      <p>We cannot promise every package works perfectly. Package inputs, review decisions, build evidence, and signatures are visible. The pipeline is designed to prevent packages from attacking users.</p>
      <div class="action-row"><a class="button" href="/docs/security">Read security controls<Icon name="arrow" size={14} /></a><a class="button button--quiet" href="/docs/reproducibility">Read build policy<Icon name="arrow" size={14} /></a></div>
    </div>
  </section>

  <footer class="site-footer">
    <p>omapkg · Omarchy Package Repository</p>
    <nav class="site-footer__links" aria-label="Footer navigation">
      <a href="/docs">Docs</a>
      <a href="/request">Request</a>
      <a href="/docs/security">Security</a>
      <a href="https://github.com/ferrreo/omapkg" rel="noreferrer">Source repository</a>
    </nav>
  </footer>
</main>
