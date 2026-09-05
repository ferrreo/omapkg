<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';

  export let data: { user?: { id: string; name?: string; image?: string | null } | null; role?: string };

  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head><title>Security controls · omapkg</title><meta name="description" content="Security boundaries and review controls in omapkg." /></svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <article class="section site-width--narrow" aria-labelledby="security-title">
    <div class="section__head"><div><h1 id="security-title">Inspect before install</h1></div><p>omapkg cannot prove that arbitrary upstream software is harmless. It ties the request, source, generated recipe, build, signature, and release decision together.</p></div>

    <div class="detail-stack">
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Source and agent boundary</h2><Icon name="lock" size={18} /></div><p class="prose">Users submit names and upstream URLs. They do not submit executable PKGBUILDs. The factory reads upstream files and submitted downloads as hostile data, has only allowlisted tools, and receives no signing keys, OAuth secrets, worker credentials, or production write access.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Build boundary</h2><Icon name="server" size={18} /></div><p class="prose">An online verification pass resolves redirects, immutable refs, checksums, licenses, dependencies, and download metadata. The factory generates a recipe from the reviewed input. After review, a controlled extractor handles supported package inputs inside the isolated offline worker; network access stays disabled while it extracts and builds. The worker uploads an attestation and artifact, then the system removes the disposable environment.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Signing and release</h2><Icon name="shield" size={18} /></div><p class="prose">A separate signing service checks the reviewed revision, manifest, worker lease, attestation, and tests before signing a binary. Every successful build enters dev. A maintainer promotes a dependency-compatible batch to stable after the published gates pass.</p></section>
      <section class="workbench-panel surface-panel--recipe"><div class="workbench-panel__head"><h2>Public data boundary</h2><Icon name="eye" size={18} /></div><p class="prose">Public package pages show approved source, license, architecture, checksums, signatures, SBOMs, attestations, tests, and channel history. Internal prompts, private credentials, worker details, and unredacted logs stay restricted.</p></section>
    </div>
  </article>

  <footer class="site-footer"><p>omapkg · security controls</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/docs">Docs</a><a href="/docs/reproducibility">Build policy</a><a href="/packages">Packages</a></nav></footer>
</main>
