<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';

  export let data: { user?: { id: string; name?: string; image?: string | null } | null; role?: string };

  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head><title>Docs · omapkg</title><meta name="description" content="How omapkg requests, reviews, builds, signs, and publishes Arch packages." /></svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="docs-title">
    <div class="section__head"><div><h1 id="docs-title">Evidence and controls</h1></div><p>These pages describe the package request flow, security boundaries, and inputs used for reproducible Arch builds.</p></div>
    <div class="surface-grid">
      <a class="surface-panel" href="/docs/security"><div class="surface-panel__top"><h2>Security controls</h2><Icon name="shield" size={20} /></div><p>How input inspection, agent tools, workers, signing, and public records are separated.</p><span class="surface-panel__meta">review before trust</span></a>
      <a class="surface-panel surface-panel--recipe" href="/docs/reproducibility"><div class="surface-panel__top"><h2>Build policy</h2><Icon name="terminal" size={20} /></div><p>How the system handles immutable Git and download inputs, dependency bundles, offline builds, and promotion gates.</p><span class="surface-panel__meta">inputs before artifacts</span></a>
    </div>
  </section>

  <section class="section site-width--narrow" aria-labelledby="flow-title"><div class="section__head"><div><span class="eyebrow">For users and maintainers</span><h2 id="flow-title">Each request passes four checks</h2></div></div><ol class="timeline"><li class="timeline__item"><strong>Request</strong><p>Submit a package name and upstream Git or direct download URL.</p></li><li class="timeline__item"><strong>Inspect</strong><p>The inspector records the input format, immutable digest, and source evidence.</p></li><li class="timeline__item"><strong>Build</strong><p>The factory generates a recipe; workers build from a sealed manifest in a disposable offline environment.</p></li><li class="timeline__item"><strong>Publish</strong><p>Signed binaries or recipe records enter dev before a maintainer decides on stable promotion.</p></li></ol></section>

  <footer class="site-footer"><p>omapkg · documentation</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/">Home</a><a href="/packages">Packages</a><a href="/request">Request</a></nav></footer>
</main>
