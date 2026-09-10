<script lang="ts">
  import { enhance } from '$app/forms';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;
  let report = '';
  let cohortId = '';
  let busy = false;
  $: if (!cohortId && data.cohorts[0]) cohortId = data.cohorts[0].id;
  $: preview = form && 'preview' in form ? form.preview : null;
  const age = (value: number | null) => value === null ? 'Unmeasured' : `${value}s`;
</script>

<svelte:head><title>Rebuild planning · omapkg</title></svelte:head>
<MaintainerShell active="rebuilds" user={data.user}>
  <section class="maintainer-page" aria-labelledby="rebuild-title">
    <header class="maintainer-page__head"><div><h1 id="rebuild-title">Rebuild planning</h1><p>Review a local planner report against current admitted catalog policies and the selected cohort’s exact recipe scope.</p></div><a class="button" href="/maintain/cohorts">Cohort workbench</a></header>
    <p class="notice-bar">Reports are proposals from already captured inventories. This screen never imports packages, runs builds, publishes releases or grants admission.</p>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{/if}

    <section class="workbench-panel" aria-labelledby="report-title">
      <h2 id="report-title">Inspect planner report</h2>
      {#if data.cohorts.length}
        <form method="POST" action="?/preview" use:enhance={() => { busy = true; return async ({ update }) => { await update(); busy = false; }; }}>
          <div class="field"><label for="rebuild-cohort">Current cohort scope</label><select id="rebuild-cohort" name="cohortId" bind:value={cohortId} required>{#each data.cohorts as cohort}<option value={cohort.id}>{cohort.title} · revision {cohort.current_revision} · {cohort.member_count} members · {cohort.phase}</option>{/each}</select><span class="field-help">Recipe bindings are read from this cohort revision; latest unreviewed recipes are never inferred.</span></div>
          <div class="field field--full"><label for="rebuild-report">Local rebuild-scope-proposal JSON</label><textarea id="rebuild-report" name="report" bind:value={report} required rows="12" spellcheck="false" placeholder="Paste the output of scripts/plan-rebuilds.ts"></textarea><span class="field-help">All-target reports cover x86_64 and aarch64. A single-target report remains diagnostic and shows its missing native target. Maximum 8 MiB.</span></div>
          <button class="button button--primary" type="submit" disabled={busy || !report.trim()}>{busy ? 'Checking report…' : 'Check current scope'}</button>
        </form>
      {:else}
        <EmptyState title="No cohort scope available." description="Create an unpublished cohort draft before attaching a rebuild proposal." actionLabel="Open cohorts" actionHref="/maintain/cohorts" />
      {/if}
    </section>

    {#if preview}
      <section class="workbench-panel" aria-labelledby="preview-title">
        <div class="workbench-panel__head"><h2 id="preview-title">Scope preview</h2><span class="tag">{preview.members.length} complete members</span></div>
        <p><strong>{preview.title}</strong> · {preview.lane === 'system' ? `system ${preview.systemVersion}` : 'independent OPR'} · current revision {preview.expectedRevision}</p>
        <p class:notice-bar={!preview.complete}>{preview.complete ? 'Current catalog and recipe mappings are complete. Report evidence blockers still require later phase review.' : 'Draft creation is blocked until every member maps to current admitted catalog and reviewed recipe scope.'}</p>
        {#if preview.blockers.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Blocker</th><th>Target</th><th>Reason</th></tr></thead><tbody>{#each preview.blockers as blocker}<tr><td>{blocker.code}</td><td>{blocker.architecture ?? 'all'}</td><td>{blocker.reason}</td></tr>{/each}</tbody></table></div>{/if}
        <div class="data-table-wrap"><table class="data-table"><thead><tr><th>Target plan</th><th>Members</th><th>Missing seeds</th><th>Source gaps</th></tr></thead><tbody>{#each preview.targetPlans as plan}<tr><td>{plan.architecture}</td><td>{plan.members}</td><td>{plan.missingSeeds.length || '—'}</td><td>{plan.sourceGaps || '—'}</td></tr>{/each}</tbody></table></div>
        <h3>Complete scope</h3><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package base</th><th>Catalog</th><th>Recipe</th><th>Cause</th></tr></thead><tbody>{#each preview.members.slice(0, 50) as member}<tr><td>{member.pkgbase}</td><td>{member.catalogRevision ?? 'Unresolved'}</td><td>{member.recipeRevisionId ?? 'Unresolved'}</td><td>{member.cause}</td></tr>{/each}</tbody></table></div>{#if preview.members.length > 50}<p class="field-help">Showing first 50 of {preview.members.length}. Draft creation retains the complete sorted scope through chunked storage.</p>{/if}
        {#if preview.complete}<form method="POST" action="?/create" use:enhance={() => { busy = true; return async ({ update }) => { await update(); busy = false; }; }}><input type="hidden" name="cohortId" value={preview.cohortId} /><input type="hidden" name="report" value={report} /><div class="field"><label for="rebuild-reason">Reason to create plan draft</label><textarea id="rebuild-reason" name="reason" required maxlength="2000" rows="2" placeholder="Review complete planner scope for the next cohort revision"></textarea></div><button class="button button--primary" type="submit" disabled={busy}>{busy ? 'Creating draft…' : 'Create plan draft'}</button></form>{/if}
      </section>
    {/if}

    <section class="workbench-panel" aria-labelledby="coverage-title">
      <div class="workbench-panel__head"><h2 id="coverage-title">Operations coverage</h2><span class="timestamp">measured {new Date(data.coverage.generatedAt * 1000).toISOString().replace('T', ' ').slice(0, 19)} UTC</span></div>
      <div class="metric-strip"><div class="metric"><span class="metric__value">{data.coverage.catalog.admitted}/{data.coverage.catalog.total}</span><span class="metric__label">current catalog policies admitted</span></div><div class="metric"><span class="metric__value">{data.coverage.checks.measured ? data.coverage.checks.records : '—'}</span><span class="metric__label">persisted cohort checks</span></div></div>
      <h3>Queue age</h3><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Architecture</th><th>Queued or leased</th><th>Oldest age</th></tr></thead><tbody>{#each data.coverage.queue as row}<tr><td>{row.architecture}</td><td>{row.queued}</td><td>{age(row.oldestAgeSeconds)}</td></tr>{/each}</tbody></table></div>
      <h3>Target parity in current recipe-bound scopes</h3><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Architecture</th><th>Scoped recipes</th><th>Succeeded builds</th><th>State</th></tr></thead><tbody>{#each data.coverage.targetParity as row}<tr><td>{row.architecture}</td><td>{row.expected}</td><td>{row.succeeded}</td><td>{row.measured ? 'Measured from builds' : 'Unmeasured'}</td></tr>{/each}</tbody></table></div>
      <h3>Check evidence</h3><p>{data.coverage.checks.measured ? `${data.coverage.checks.records} immutable cohort check record(s) stored.` : 'No cohort check evidence is stored; coverage is unmeasured.'}</p>
    </section>
  </section>
</MaintainerShell>
