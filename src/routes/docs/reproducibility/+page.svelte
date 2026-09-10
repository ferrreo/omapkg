<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';

  export let data: { user?: { id: string; name?: string; image?: string | null } | null; role?: string };

  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head><title>Reproducibility contract · omapkg</title><meta name="description" content="Single-build reproducibility contract, output inspection, and independent reproduction evidence for omapkg." /></svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <article class="section site-width--narrow" aria-labelledby="build-policy-title">
    <div class="section__head"><div><h1 id="build-policy-title">Reproducibility contract</h1></div><p>Each normal candidate builds once per required native target. Release evidence says exactly what that execution observed and what it cannot establish.</p></div>

    <div class="detail-stack">
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Seal inputs</h2><Icon name="git" size={18} /></div><p class="prose">Git sources resolve to immutable commits. Recipes retain source, submodule, LFS, vendor, dependency, toolchain, builder-image, runtime-image, and image-definition digests. Missing locks, mutable references, or incomplete replay inputs block the build.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Observe one build</h2><Icon name="terminal" size={18} /></div><p class="prose">The worker builds in a fresh network-disabled environment with fixed C locale, UTC, umask 022, SOURCE_DATE_EPOCH, native target, isolated writable paths, and no inherited host secrets or shared output cache. It records actual worker, run, recipe, input, environment, command, and output identities.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Inspect every output</h2><Icon name="box" size={18} /></div><p class="prose">The contract checks the complete output set, names, sizes, SHA-256 digests, package metadata, archive paths, split/debug outputs, smoke results, and runtime analysis. Archive inspection reports its limits; static checks cannot prove arbitrary upstream code is deterministic.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Read evidence labels</h2><Icon name="check" size={18} /></div><p class="prose"><strong>Reproducibility contract verified</strong> means one trusted execution observed the required inputs and controls and authenticated its outputs. <strong>Independently reproduced</strong> means two actual builds from fresh roots matched final unsigned bytes. Historical, unknown, and mismatch records keep their original labels. Normal release requires the contract; it does not schedule a duplicate build.</p></section>
      <section class="workbench-panel surface-panel--recipe"><div class="workbench-panel__head"><h2>Run native qualification</h2><Icon name="shield" size={18} /></div><p class="prose">Install, upgrade, recovery, and boot checks remain separate native qualification operations. An independently supplied reproduction can be retained as additional evidence through the reviewed plan flow:</p><p class="prose"><code>opr-worker qualification --origin https://… --plan-id PLAN_ID --config /var/lib/opr-worker/config.json --output /var/lib/opr-worker/qualification.json --submit</code></p><p class="prose">The command verifies the exact reviewed plan, worker identity, target architecture, observed state, and signatures. It does not turn an independent report into a second normal package build.</p></section>
    </div>
  </article>

  <footer class="site-footer"><p>omapkg · build policy</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/docs">Docs</a><a href="/docs/security">Security controls</a><a href="/packages">Packages</a></nav></footer>
</main>
