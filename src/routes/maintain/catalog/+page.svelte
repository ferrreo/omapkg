<script lang="ts">
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import CatalogPolicyForm from '$lib/components/CatalogPolicyForm.svelte';
  import { collections } from '$lib/distribution';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;

  export let form: ActionData;
</script>
<svelte:head><title>Catalog ownership · omapkg</title></svelte:head>
<MaintainerShell active="catalog" user={data.user}>
  <section class="maintainer-page" aria-labelledby="catalog-title">
    <header class="maintainer-page__head"><div><h1 id="catalog-title">Catalog ownership</h1><p>Review package identity, source, release policy and target support before builds enter an owned repository.</p></div><a class="button" href="/maintain/dependencies">Dependency proposals</a></header>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{/if}
    <form class="filter-bar" method="GET"><div class="field"><label for="catalog-search">Search packages</label><input id="catalog-search" name="q" type="search" value={data.search} /></div><div class="field"><label for="catalog-filter">Repository</label><select id="catalog-filter" name="collection" value={data.collection}><option value="">All repositories</option>{#each collections as item}<option value={item}>{item}</option>{/each}</select></div><button class="button" type="submit">Search catalog</button></form>
    {#if data.packages.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Repository / release policy</th><th>Owner</th><th>Ownership review</th></tr></thead><tbody>{#each data.packages as pkg}<tr><td><a href={`/maintain/catalog/${encodeURIComponent(pkg.pkgbase)}`}>{pkg.pkgbase}</a></td><td>{pkg.collection} · {pkg.lane === 'system' ? 'Versioned system' : 'Independent OPR'}</td><td>{pkg.owner_area}</td><td>{pkg.admitted_revision === pkg.current_revision ? 'Admitted' : 'Review required'}<div class="timestamp">Revision {pkg.current_revision}{#if pkg.admitted_revision && pkg.admitted_revision !== pkg.current_revision} · revision {pkg.admitted_revision} remains admitted{/if}</div></td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No catalog policies match." description="Capture an import inventory or propose a package policy. Unreviewed records are never counted as admitted packages." />{/if}
    {#if data.packages.length === 50}<a class="button" href={`?${new URLSearchParams({ q: data.search, collection: data.collection, after: data.packages.at(-1)!.pkgbase })}`}>Next packages</a>{/if}
    <details class="workbench-panel"><summary>Propose a catalog package</summary><CatalogPolicyForm /></details>
  </section>
</MaintainerShell>
