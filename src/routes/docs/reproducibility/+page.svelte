<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';

  export let data: { user?: { id: string; name?: string; image?: string | null } | null; role?: string };

  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head><title>Build policy · omapkg</title><meta name="description" content="Source, dependency, and offline build policy for omapkg." /></svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <article class="section site-width--narrow" aria-labelledby="build-policy-title">
    <div class="section__head"><div><h1 id="build-policy-title">Build inputs</h1></div><p>Reproducible build inputs start at request time. Bit-for-bit verification is a later milestone; the first release records the controls needed to support it.</p></div>

    <div class="detail-stack">
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Resolve input</h2><Icon name="git" size={18} /></div><p class="prose">Git branches resolve to an immutable commit. The inspector records direct download metadata, final URL, detected format, and pinned byte digest online. After review, a controlled extractor handles supported tar, zip, deb, rpm, AppImage, and .run inputs inside the isolated offline build; unsupported formats stop with a recorded reason.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Seal dependencies</h2><Icon name="box" size={18} /></div><p class="prose">The factory prefers Arch or omapkg packages where available. When vendoring is required, online verification creates a checksum-bound bundle and SBOM. The worker receives those bytes through the reviewed manifest.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Build offline</h2><Icon name="terminal" size={18} /></div><p class="prose">Arch devtools run in a disposable environment with network access disabled. The job records architecture, builder image digest, source date, recipe hash, source manifest, smoke tests, and output hashes.</p></section>
      <section class="workbench-panel surface-panel--recipe"><div class="workbench-panel__head"><h2>Promote with evidence</h2><Icon name="check" size={18} /></div><p class="prose">Successful builds enter dev. Maintainers check quarantine time, smoke tests, crash evidence, and dependency readiness before making the promotion decision. Stable publication keeps older versions addressable for rollback.</p></section>
    </div>
  </article>

  <footer class="site-footer"><p>omapkg · build policy</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/docs">Docs</a><a href="/docs/security">Security controls</a><a href="/packages">Packages</a></nav></footer>
</main>
