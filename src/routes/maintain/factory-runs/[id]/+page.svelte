<script lang="ts">
  import { enhance } from '$app/forms';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;
</script>

<svelte:head><title>Factory run · {data.run.targetId} · omapkg</title></svelte:head>
<MaintainerShell active="queue" user={data.user || null}>
  <section class="maintainer-page" aria-labelledby="run-title">
    <header class="maintainer-page__head">
      <div><span class="eyebrow">Private factory run</span><h1 id="run-title">{data.run.targetId}</h1><p>{data.run.targetKind} · {data.run.unitKey}</p></div>
      <div>{data.run.status} · {data.run.attemptCount}/{data.run.maxAttempts} attempts</div>
    </header>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{/if}
    {#if form?.stopped}<p class="notice-bar" role="status">Run stopped. Its attempts and logs are retained below.</p>{/if}
    {#if form?.successorId}<p class="notice-bar" role="status">New bounded run authorized. <a href={form.successorRequestId ? `/maintain/requests/${encodeURIComponent(form.successorRequestId)}` : `/maintain/factory-runs/${encodeURIComponent(form.successorId)}`}>Open successor work</a>.</p>{/if}
    {#if data.run.sourceRunId}<p>Continues <a href={`/maintain/factory-runs/${encodeURIComponent(data.run.sourceRunId)}`}>{data.run.sourceRunId}</a>. Earlier attempts remain in that run.</p>{/if}
    {#if data.requestId}<p><a href={`/maintain/requests/${encodeURIComponent(data.requestId)}`}>Open recipe, review decisions, or rejection controls</a></p>{/if}
    {#if data.canStop && ['queued', 'running'].includes(data.run.status)}
      <form class="review-form" method="POST" action="?/stop" use:enhance>
        <div class="field"><label for="stop-reason">Reason to stop</label><input id="stop-reason" name="reason" required maxlength="2000" /></div>
        <button class="button button--danger" type="submit">Stop automatic attempts</button>
      </form>
    {/if}
    <section class="workbench-panel" aria-labelledby="attempts-title">
      <h2 id="attempts-title">Retained attempts</h2>
      {#each data.attempts as attempt}
        <article>
          <h3>Attempt {attempt.attempt} · {attempt.status}</h3>
          <p>Recipe revision: <code>{attempt.candidateRevisionId ?? 'None'}</code></p>
          <p>Candidate: <code>{attempt.candidateSha256}</code></p><p>Inputs: <code>{attempt.inputSha256}</code></p>
          <ul>{#each attempt.buildIds as id}<li><a href={`/maintain/builds/${encodeURIComponent(id)}`}>Build {id}</a></li>{/each}</ul>
          {#if attempt.failureKind}<p>{attempt.failureKind}</p><pre>{attempt.failure}</pre>{/if}
        </article>
      {:else}<p>No attempt has been reserved.</p>{/each}
    </section>
    <section class="workbench-panel" aria-labelledby="dossiers-title">
      <h2 id="dossiers-title">Dossier snapshots</h2>
      <ul>
        {#each data.dossiers as dossier}<li><a href={`/maintain/dossiers/${encodeURIComponent(dossier.id)}`}>{dossier.revision_id}</a></li>{/each}
        {#each data.aggregateDossiers as dossier}<li><a href={`/maintain/dossiers/aggregate/${encodeURIComponent(dossier.id)}`}>{dossier.target_kind} · {dossier.id}</a></li>{/each}
        {#if !data.dossiers.length && !data.aggregateDossiers.length}<li>No snapshot saved.</li>{/if}
      </ul>
    </section>
    {#if data.pagedCohortCoordinator}
      <section class="workbench-panel" aria-labelledby="cohort-members-title">
        <h2 id="cohort-members-title">Cohort member runs</h2>
        <p>Review failed member runs and authorize new attempts individually.</p>
        <p><a href={`/maintain/cohorts/${encodeURIComponent(data.run.targetId)}`}>Open cohort</a></p>
        <ul>{#each data.cohortChildren as child}<li><a href={`/maintain/factory-runs/${encodeURIComponent(child.id)}`}>{child.unit_key}</a> · {child.status}</li>{:else}<li>No member runs retained yet.</li>{/each}</ul>
      </section>
    {/if}
    {#if data.run.status === 'needs-human-intervention'}
      <section class="workbench-panel" aria-labelledby="intervention-title">
        <h2 id="intervention-title">Human intervention required</h2>
        <pre>{data.run.failure}</pre>
        <p>Review failed checks and retained repairs. A new authorization creates a separate run with at most three attempts and preserves this history.</p>
        {#if data.canIntervene}
          <form method="POST" action="?/intervene" use:enhance>
            <label for="intervention-reason">Guidance and reason for another bounded run</label>
            <textarea id="intervention-reason" name="reason" required maxlength="2000" rows="5">{form?.reason ?? ''}</textarea>
            <button class="button button--primary" type="submit">Authorize successor run</button>
          </form>
        {:else if data.pagedCohortCoordinator}
          <p>Coordinator intervention is unavailable. Use links above to open an exhausted cohort member run.</p>
        {:else if data.run.targetKind === 'image'}
          <p>No retained image candidate is available for a safe successor run.</p>
        {/if}
      </section>
    {/if}
    <details class="workbench-panel"><summary>Approved execution scope</summary><pre>{data.run.policy}</pre></details>
  </section>
</MaintainerShell>

<style>
  article { padding-block: 1rem; border-bottom: var(--border-width) solid var(--color-rule); }
  code, pre { overflow-wrap: anywhere; }
  pre { white-space: pre-wrap; max-width: 100%; overflow: auto; }
  form { display: grid; gap: 1rem; }
  textarea { width: 100%; box-sizing: border-box; }
</style>
