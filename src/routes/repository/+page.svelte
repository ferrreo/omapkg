<script lang="ts">
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { PageData } from './$types';
  export let data: PageData;
  const date = (timestamp: number) => new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
</script>
<svelte:head><title>Repository status · omapkg</title><meta name="description" content="Published package repository availability for x86_64 and ARM." /></svelte:head>
<PublicNav user={data.user} role={data.role} />
<main class="public-main"><section class="section site-width--narrow" aria-labelledby="repository-title">
  <div class="section__head"><div><h1 id="repository-title">Repository status</h1><p>Published packages and repository availability, shown separately for each architecture.</p></div></div>
  <p class="timestamp">Checked {date(data.checkedAt)}. Reload to check again.</p>
  <section class="release-projection" aria-labelledby="release-projection-title">
    <div><p class="eyebrow">Published release projection</p><h2 id="release-projection-title">System and OPR remain separate</h2><p>{data.notice}</p></div>
    <div class="release-projection__lanes">
      <article><h3>System release</h3>{#if data.systemRelease}<p class="system-version">Omarchy {data.systemRelease.version ?? 'Version not recorded'}</p><p>{data.systemRelease.status}</p><span class="hash">{data.systemRelease.digest ?? 'Manifest digest not recorded'}</span>{:else}<p>No system release manifest is published in this projection.</p><a href="/releases">Inspect system release records</a>{/if}</article>
      <article><h3>Independent OPR</h3><p>{data.oprReleases.length} published package record{data.oprReleases.length === 1 ? '' : 's'} in current projection.</p><p>Package versions and generations stay independent from the system version.</p><a href="/releases">View compatibility and changelogs</a></article>
    </div>
  </section>
  {#if data.releaseManifests.length}<section class="release-manifests" aria-labelledby="release-manifests-title"><div><p class="eyebrow">Active versioned repositories</p><h2 id="release-manifests-title">Exact system and OPR snapshots</h2><p>Each row is bound to an immutable release manifest and target-specific database/signature URLs.</p></div>{#each data.releaseManifests as manifest}<article><header><h3>{manifest.kind === 'system' ? `Omarchy ${manifest.version ?? 'version not recorded'}` : `OPR ${manifest.generation ?? 'generation not recorded'}`}</h3><span class="tag">sequence {manifest.sequence}</span></header><div class="release-manifests__grid">{#each manifest.repositories as repository}<div><strong>{repository.name ?? 'repository'} · {repository.architecture}</strong><span>{repository.packageCount ?? 'Package count not recorded'} package{repository.packageCount === 1 ? '' : 's'}</span><span class="hash">{repository.digest ?? 'Snapshot digest not recorded'}</span><p>{#if repository.databaseUrl}<a href={repository.databaseUrl}>Database</a>{/if}{#if repository.signatureUrl}<a href={repository.signatureUrl}>Signature</a>{/if}</p></div>{/each}</div></article>{/each}</section>{:else}<p class="release-manifests__empty">No active versioned system or OPR repository manifest is published for this projection.</p>{/if}
  {#each ['stable', 'dev'] as channel}<section class="repository-section" aria-labelledby={`${channel}-title`}><h2 id={`${channel}-title`}>{channel === 'stable' ? 'Stable OPR packages' : 'OPR testing quarantine'}</h2><p>{channel === 'stable' ? 'Independent package updates currently published for users.' : 'Explicit opt-in package testing. This is separate from a versioned system edge or RC release.'}</p>
    <div class="repository-grid">{#each data.repositories.filter((item) => item.channel === channel) as repository}<article class="repository-card"><h3>{repository.architecture === 'aarch64' ? 'ARM · aarch64' : 'x86_64'}</h3><p><strong>{repository.state === 'available' ? 'Database available' : repository.state === 'not-published' ? 'Database not published' : 'Database unavailable'}</strong></p>
      <dl><div><dt>Binary packages</dt><dd>{repository.binaryPackages}</dd></div><div><dt>Recipe-only packages</dt><dd>{repository.recipePackages}</dd></div></dl>
      {#if repository.publishedAt}<p class="timestamp">Database published {date(repository.publishedAt)}</p>{/if}
      {#if repository.state === 'available'}<p>Database and detached signature are reachable. Package-specific build and runtime evidence appears in the catalog.</p>{:else if repository.state === 'unavailable'}<p>Published database or signature could not be reached. Retry before starting an update.</p>{:else}<p>No binary repository database is active for this target. Recipe-only releases may still be listed.</p>{/if}
      <div class="repository-links"><a href={`/packages?architecture=${repository.architecture}&channel=${repository.channel}`}>Browse published packages</a>{#if repository.databaseUrl && repository.signatureUrl}<a href={repository.databaseUrl}>Repository database</a><a href={repository.signatureUrl}>Detached signature</a>{/if}</div>
    </article>{/each}</div>
  </section>{/each}
  <p><a href="/docs">Read installation and verification instructions</a>. Repository availability does not establish whole-system compatibility or reproducibility.</p>
</section></main>
<style>
  .repository-section { margin-block: 2rem; }
  .release-projection { border-block: 1px solid var(--color-rule); display: grid; gap: 1rem; margin-block: 2rem 3rem; padding-block: 1.25rem; }
  .release-projection > div:first-child { display: grid; gap: .5rem; }
  .release-projection__lanes { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit,minmax(min(100%,280px),1fr)); }
  .release-projection__lanes article { background: var(--color-surface); border-left: .2rem solid var(--color-accent); display: grid; gap: .5rem; min-width: 0; padding: 1.25rem; }
  .release-projection__lanes article + article { border-left-color: var(--color-positive); }
  .release-projection__lanes p { color: var(--color-text); font-family: var(--font-body); }
  .system-version { color: var(--color-accent-strong) !important; font-size: var(--text-md); font-weight: 700; }
  .release-manifests { display: grid; gap: 1rem; margin-block: 2rem; }
  .release-manifests > div { display: grid; gap: .5rem; }
  .release-manifests article { background: var(--color-surface); border-block: 1px solid var(--color-rule-soft); display: grid; gap: 1rem; padding: 1.25rem; }
  .release-manifests header { align-items: baseline; display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; }
  .release-manifests__grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit,minmax(min(100%,280px),1fr)); }
  .release-manifests__grid > div { border-top: 1px solid var(--color-rule-soft); display: grid; gap: .35rem; min-width: 0; padding-top: .75rem; }
  .release-manifests__grid span { color: var(--color-text-muted); font-size: var(--text-sm); overflow-wrap: anywhere; }
  .release-manifests__grid p { display: flex; flex-wrap: wrap; gap: 1rem; margin: 0; }
  .release-manifests__empty { color: var(--color-text-muted); font-family: var(--font-body); margin-block: 2rem; }
  .repository-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(min(100%,280px),1fr)); gap: 1rem; }
  .repository-card { min-width: 0; border: 1px solid var(--color-rule); padding: 1.25rem; border-radius: .5rem; }
  .repository-card h3 { margin-top: 0; }
  .repository-card dl div { display: flex; justify-content: space-between; gap: 1rem; margin-block: .5rem; }
  .repository-card dd { margin: 0; }
  .repository-links { display: flex; flex-wrap: wrap; gap: .7rem 1rem; }
</style>
