<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import type { Build, PackageRequest } from '$lib/model';
  import type { PageData } from './$types';

  export let data: PageData;

  $: requests = (Array.isArray(data?.requests) ? data.requests : []) as PackageRequest[];
  $: builds = (Array.isArray(data?.builds) ? data.builds : []) as Array<Build & { name: string }>;
  $: counts = data?.counts || {};
  $: user = data?.user || null;

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }
</script>

<svelte:head><title>Maintainer workspace · omapkg</title></svelte:head>

<MaintainerShell active="queue" {user}>
  <section class="maintainer-page" aria-labelledby="workspace-title">
    <header class="maintainer-page__head">
      <div><span class="eyebrow">Area queues · security gates · release evidence</span><h1 id="workspace-title">Review queue</h1><p>Requests start with a name and upstream URL. Generated recipes, source manifests, builds, and promotions stay reviewable.</p></div>
      <a class="button button--primary" href="/maintain/requests">Open request queue<Icon name="arrow" size={14} /></a>
    </header>

    {#if Object.keys(counts).length}
      <div class="metric-strip" aria-label="Workspace counts">
        <div class="metric"><span class="metric__value">{counts.pending ?? '—'}</span><span class="metric__label">pending requests</span></div>
        <div class="metric"><span class="metric__value">{counts.review ?? '—'}</span><span class="metric__label">in review</span></div>
        <div class="metric"><span class="metric__value">{counts.building ?? '—'}</span><span class="metric__label">active builds</span></div>
      </div>
    {/if}

    <div class="dashboard-grid">
      <section class="workbench-panel" aria-labelledby="requests-title">
        <div class="workbench-panel__head"><h2 id="requests-title">Requests waiting</h2><a href="/maintain/requests">All requests<Icon name="arrow" size={14} /></a></div>
        {#if requests.length}
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Package</th><th>Area</th><th>Status</th><th>Updated</th></tr></thead>
              <tbody>
        {#each requests.slice(0, 12) as request}
                  <tr><td><a href={`/maintain/requests/${encodeURIComponent(request.id)}`}>{request.name}</a><div class="timestamp">{request.id}</div></td><td>{request.area}</td><td><StatusPill status={request.status} /></td><td>{formatDate(request.updated_at)}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <EmptyState title="No requests in queue." description="New package requests will appear here after authenticated intake and area assignment." actionLabel="View public intake" actionHref="/request" icon="archive" />
        {/if}
      </section>

      <section class="workbench-panel" aria-labelledby="pipeline-title">
        <div class="workbench-panel__head"><h2 id="pipeline-title">Pipeline</h2><span class="timestamp">live state</span></div>
        <ol class="timeline">
          <li class="timeline__item"><strong>Area review</strong><span class="timestamp">{counts.pending ?? '—'} pending</span><p>Validate the request and upstream source.</p></li>
          <li class="timeline__item"><strong>Factory output</strong><span class="timestamp">{counts.generating ?? '—'} generating</span><p>Inspect generated PKGBUILD and manifest.</p></li>
          <li class="timeline__item"><strong>Build evidence</strong><span class="timestamp">{counts.building ?? '—'} building</span><p>Follow leases, smoke tests, and attestations.</p></li>
          <li class="timeline__item"><strong>Release decision</strong><span class="timestamp">{counts.built ?? '—'} ready</span><p>Promote compatible batches to stable.</p></li>
        </ol>
      </section>
    </div>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="builds-title">
        <div class="workbench-panel__head"><h2 id="builds-title">Recent builds</h2><a href="/maintain/workers">Worker fleet<Icon name="arrow" size={14} /></a></div>
      {#if builds.length}
        <div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Architecture</th><th>Status</th><th>Worker</th><th>Attempt</th></tr></thead><tbody>{#each builds.slice(0, 12) as build}<tr><td><a href={`/maintain/builds/${encodeURIComponent(build.id)}`}>{build.name}</a><div class="timestamp">{build.id}</div></td><td>{build.architecture}</td><td><StatusPill status={build.status} /></td><td>{build.worker_id || 'Unassigned'}</td><td>{build.attempt}</td></tr>{/each}</tbody></table></div>
      {:else}
        <EmptyState title="No builds are running." description="Build leases and attestation evidence appear after a reviewed revision reaches the worker queue." icon="activity" />
      {/if}
    </section>
  </section>
</MaintainerShell>
