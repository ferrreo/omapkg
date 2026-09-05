<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import type { PackageRequest } from '$lib/model';
  import type { PageData } from './$types';

  export let data: PageData;

  type LabelledRequest = PackageRequest & Record<string, unknown>;
  $: requests = (Array.isArray(data?.requests) ? data.requests : []) as LabelledRequest[];
  let query = '';
  let status = '';
  let area = '';
  $: filtered = requests.filter((request) => {
    const text = `${request.name} ${request.id} ${request.upstream_url} ${requesterLabel(request)}`.toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (!status || request.status === status) && (!area || request.area === area);
  });
  $: actorNames = ((data as unknown as { actorNames?: Record<string, string> })?.actorNames || {}) as Record<string, string>;
  $: user = data?.user || null;

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  function requesterLabel(request: LabelledRequest) {
    const record = request as Record<string, unknown>;
    const display = ['requested_by_name', 'requested_by_login', 'requester_name', 'requester_login']
      .map((key) => record[key]).find((value): value is string => typeof value === 'string' && value.trim().length > 0);
    if (display) return display;
    if (actorNames[request.requested_by]) return actorNames[request.requested_by];
    if (request.requested_by.startsWith('github:')) return 'GitHub user';
    if (request.requested_by.startsWith('user:')) return 'Signed-in user';
    return request.requested_by;
  }
</script>

<svelte:head><title>Requests · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="requests" {user}>
  <section class="maintainer-page" aria-labelledby="requests-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Area queues</span><h1 id="requests-title">Request queue</h1><p>Claim, review, and route requests before the factory sees them.</p></div><a class="button" href="/request"><Icon name="external" size={14} />Public intake</a></header>

    <form class="filter-bar" method="GET">
      <div class="field"><label for="query">Search</label><input id="query" name="q" type="search" bind:value={query} placeholder="Name, ID, or source URL" /></div>
      <div class="field"><label for="request-status">Status</label><select id="request-status" name="status" bind:value={status}><option value="">All statuses</option><option value="pending">Pending</option><option value="generating">Generating</option><option value="review">Review</option><option value="building">Building</option><option value="built">Built</option><option value="failed">Failed</option><option value="rejected">Rejected</option></select></div>
      <div class="field"><label for="request-area">Area</label><select id="request-area" name="area" bind:value={area}><option value="">All areas</option><option value="desktop">Desktop</option><option value="development">Development</option><option value="gaming">Gaming</option><option value="multimedia">Multimedia</option><option value="productivity">Productivity</option><option value="system">System</option></select></div>
      <button class="button button--primary" type="submit"><Icon name="search" size={15} />Filter</button>
    </form>

    {#if requests.length && filtered.length}
      <div class="workbench-panel"><div class="workbench-panel__head"><h2>{filtered.length} request{filtered.length === 1 ? '' : 's'}</h2><span class="timestamp">current state</span></div><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Area</th><th>Status</th><th>Requested by</th><th>Updated</th></tr></thead><tbody>{#each filtered as request}<tr><td><a href={`/maintain/requests/${encodeURIComponent(request.id)}`}>{request.name}</a><div class="timestamp">{request.id}</div></td><td>{request.area}</td><td><StatusPill status={request.status} /></td><td>{requesterLabel(request)}</td><td>{formatDate(request.updated_at)}</td></tr>{/each}</tbody></table></div></div>
    {:else if requests.length}
      <EmptyState title="No requests match those filters." description="Change a filter to inspect an existing request." actionLabel="Clear filters" actionHref="/maintain/requests" icon="search" />
    {:else}
      <EmptyState title="Queue is empty." description="Authenticated requests appear here after intake and area assignment." actionLabel="Open public intake" actionHref="/request" icon="archive" />
    {/if}
  </section>
</MaintainerShell>
