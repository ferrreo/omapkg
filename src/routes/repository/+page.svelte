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
  .repository-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(min(100%,280px),1fr)); gap: 1rem; }
  .repository-card { min-width: 0; border: 1px solid var(--color-rule); padding: 1.25rem; border-radius: .5rem; }
  .repository-card h3 { margin-top: 0; }
  .repository-card dl div { display: flex; justify-content: space-between; gap: 1rem; margin-block: .5rem; }
  .repository-card dd { margin: 0; }
  .repository-links { display: flex; flex-wrap: wrap; gap: .7rem 1rem; }
</style>
