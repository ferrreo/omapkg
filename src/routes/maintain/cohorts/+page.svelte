<script lang="ts">
  import { enhance } from '$app/forms';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import { cohortPhaseLabels } from '$lib/distribution';
  import { cohortCauses } from '$lib/cohorts';
  import type { ActionData, PageData } from './$types';
  export let data: PageData;
  export let form: ActionData;
  let selection = '';
  let lane = 'system';
  let busy = false;
  $: if (!selection && data.packages[0]) selection = data.packages[0].pkgbase;
  $: selected = data.packages.find((item) => item.pkgbase === selection) ?? data.packages[0];
  $: if (selected) lane = selected.lane;
</script>
<svelte:head><title>Build cohorts · omapkg</title></svelte:head>
<MaintainerShell active="cohorts" user={data.user}>
  <section class="maintainer-page">
    <header class="maintainer-page__head"><div><h1>Build cohorts</h1><p>Packages that must build and update together. Each revision keeps its own changes, native results and phase history.</p></div></header>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{/if}
    <form method="GET" class="filter-grid" aria-label="Filter cohorts">
      <div class="field"><label for="cohort-search">Search cohorts</label><input id="cohort-search" name="q" value={data.filters.q} maxlength="100" /></div>
      <div class="field"><label for="lane-filter">Release policy</label><select id="lane-filter" name="lane"><option value="">Both</option><option value="system" selected={data.filters.lane === 'system'}>System</option><option value="opr" selected={data.filters.lane === 'opr'}>Independent OPR</option></select></div>
      <div class="field"><label for="phase-filter">Phase</label><select id="phase-filter" name="phase"><option value="">All phases</option>{#each data.phases as phase}<option value={phase} selected={data.filters.phase === phase}>{cohortPhaseLabels[phase]}</option>{/each}</select></div><button class="button" type="submit">Filter</button>
    </form>
    {#if data.cohorts.length}<section class="workbench-panel" aria-label="Cohort results">{#each data.cohorts as cohort}<article class="cohort-row"><div><a href={`/maintain/cohorts/${encodeURIComponent(cohort.id)}`}><strong>{cohort.title}</strong></a><p>{cohort.lane === 'system' ? 'System release' : 'Independent OPR'} · revision {cohort.current_revision} · {cohort.member_count} package{cohort.member_count === 1 ? '' : 's'}</p></div><p>{cohortPhaseLabels[cohort.phase]} · {cohort.condition}</p></article>{/each}</section>{:else}<EmptyState title="No matching cohorts" description="Create a draft from an owned catalog identity. Admission, recipe review and publication remain separate decisions." />{/if}
    {#if data.cohorts.length === 50}<a class="button" href={`?${new URLSearchParams({ ...data.filters, after: data.cohorts.at(-1)!.id })}`}>Next cohorts</a>{/if}
    <section class="workbench-panel"><h2>Plan a cohort</h2><p>Start with one package, then add affected providers and consumers. A draft grants no build or release approval.</p>
      <form method="GET" class="search-form"><div class="field"><label for="package-search">Find a catalog package</label><input id="package-search" name="package" value={data.selectedPackage} maxlength="100" /></div><button class="button" type="submit">Find package</button></form>
      {#if selected}<form method="POST" action="?/create" class="review-form" use:enhance={() => { busy = true; return async ({ update }) => { await update(); busy = false; }; }}>
        <input type="hidden" name="cohortId" value={data.cohortId} /><input type="hidden" name="catalogRevision" value={selected.revision} />
        <div class="field"><label for="package">First member</label><select id="package" name="pkgbase" bind:value={selection}>{#each data.packages as pkg}<option value={pkg.pkgbase}>{pkg.pkgbase} · {pkg.collection} · policy {pkg.revision}</option>{/each}</select></div>
        <div class="field"><label for="title">What changes together?</label><input id="title" name="title" placeholder="Example library transition" required maxlength="160" /></div>
        <div class="field"><label for="lane">Release policy</label><select id="lane" name="lane" bind:value={lane}><option value="system">Versioned system release</option><option value="opr">Independent OPR update</option></select></div>
        {#if lane === 'system'}<div class="field"><label for="system-version">Planned system version</label><input id="system-version" name="systemVersion" placeholder="4.0.3-rc2" required /><span class="field-help">Planning does not reserve or publish this version.</span></div>{/if}
        <div class="field"><label for="cause">Change cause</label><select id="cause" name="cause">{#each cohortCauses as cause}<option value={cause}>{cause.replaceAll('-', ' ')}</option>{/each}</select></div>
        <div class="field"><label for="reason">Why this cohort is needed</label><textarea id="reason" name="reason" required maxlength="2000" rows="3"></textarea></div>
        <button class="button button--primary" disabled={busy} type="submit">{busy ? 'Creating draft…' : 'Create cohort draft'}</button>
      </form>{:else}<p>No catalog packages match. <a href="/maintain/catalog">Propose a catalog identity</a> first.</p>{/if}
    </section>
  </section>
</MaintainerShell>
<style>
  .filter-grid { display: flex; flex-wrap: wrap; align-items: end; gap: 1rem; }
  .filter-grid .field { flex: 1 1 180px; min-width: 0; }
  .search-form { display: flex; align-items: end; flex-wrap: wrap; gap: 1rem; margin-block: 1rem; }
  .search-form .field { flex: 1 1 240px; }
  .cohort-row { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 1rem; padding-block: 1rem; border-bottom: 1px solid var(--color-rule); }
  .cohort-row p { margin-block: .35rem; }
</style>
