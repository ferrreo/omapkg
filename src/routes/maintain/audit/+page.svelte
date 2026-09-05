<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import AuditEvent from '$lib/components/AuditEvent.svelte';
  import type { AuditEvent as AuditEventRecord } from '$lib/model';
  import type { PageData } from './$types';

  export let data: PageData;

  type AuditRange = 'all' | '24h' | '7d' | '30d' | '90d';
  const rangeOptions: Array<{ value: AuditRange; label: string }> = [
    { value: 'all', label: 'All time' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
    { value: '90d', label: 'Last 90 days' }
  ];

  $: events = (Array.isArray(data?.events) ? data.events : []) as AuditEventRecord[];
  $: actorNames = ((data as unknown as { actorNames?: Record<string, string> })?.actorNames || {}) as Record<string, string>;
  $: user = data?.user || null;
  $: requestId = ((data as unknown as { requestId?: string })?.requestId || '').trim();
  let query = data?.query || '';
  let range = (data?.range || 'all') as AuditRange;
  $: nextBefore = data?.nextBefore ?? null;
  $: exportScope = makeScopeParams(query, range, requestId, data?.range, data?.from, data?.to);
  $: csvHref = `/api/admin/audit/export?${new URLSearchParams([...exportScope, ['format', 'csv']]).toString()}`;
  $: ndjsonHref = `/api/admin/audit/export?${new URLSearchParams([...exportScope, ['format', 'ndjson']]).toString()}`;
  $: nextHref = nextBefore === null ? '' : `/maintain/audit?${new URLSearchParams([...exportScope, ['before', String(nextBefore)]]).toString()}`;
  $: clearHref = requestId ? `/maintain/audit?request=${encodeURIComponent(requestId)}` : '/maintain/audit';
  $: allHref = requestId ? `/maintain/audit?request=${encodeURIComponent(requestId)}&range=all` : '/maintain/audit';

  function scopeLabel(value: AuditRange) {
    return rangeOptions.find((option) => option.value === value)?.label || 'All time';
  }

  function makeScopeParams(currentQuery: string, currentRange: AuditRange, currentRequestId: string, loadedRange: AuditRange | undefined, from: number | null | undefined, to: number | null | undefined) {
    const params = new URLSearchParams({ q: currentQuery.trim(), range: currentRange });
    if (currentRequestId) params.set('request', currentRequestId);
    if (loadedRange === currentRange) {
      if (from !== null && from !== undefined) params.set('from', String(from));
      if (to !== null && to !== undefined) params.set('to', String(to));
    }
    return params;
  }
</script>

<svelte:head><title>Audit log · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="audit" {user}>
  <section class="maintainer-page" aria-labelledby="audit-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Append-only audit · correlated and redacted</span><h1 id="audit-title">Audit log</h1><p>Security-sensitive actions carry an actor, target, reason, result, and correlation context. Public package pages receive only approved evidence.</p></div><span class="tag tag--accent"><Icon name="lock" size={13} />maintainer only</span></header>

    <form class="filter-bar" method="GET">
      <div class="field"><label for="audit-search">Search events</label><input id="audit-search" name="q" type="search" bind:value={query} placeholder="Actor, action, target, detail" /></div>
      <div class="field"><label for="audit-range">Range</label><select id="audit-range" name="range" bind:value={range}>{#each rangeOptions as option}<option value={option.value}>{option.label}</option>{/each}</select></div>
      {#if requestId}<input type="hidden" name="request" value={requestId} />{/if}
      <button class="button button--primary" type="submit"><Icon name="search" size={15} />Apply scope</button>
    </form>

    <div class="release-actions" aria-label="Export selected audit scope">
      <span class="field__hint">Export scope: {scopeLabel(range)}{query.trim() ? ` · ${query.trim()}` : ''}</span>
      <a class="button" href={csvHref} download><Icon name="download" size={14} />CSV</a>
      <a class="button" href={ndjsonHref} download><Icon name="download" size={14} />NDJSON</a>
    </div>

    {#if events.length}
      <section class="workbench-panel" aria-label="Audit events"><div class="workbench-panel__head"><h2>{events.length} event{events.length === 1 ? '' : 's'}</h2><span class="timestamp">{scopeLabel(range)}{requestId ? ` · request ${requestId}` : ''} · server query</span></div><div class="audit-list">{#each events as event}<AuditEvent {event} {actorNames} />{/each}</div></section>
      {#if nextHref}<nav class="release-actions" aria-label="Audit pagination"><a class="button" href={nextHref}><Icon name="arrow" size={14} />Older events</a></nav>{/if}
    {:else if data?.query}
      <EmptyState title="No events match that search." description="Try an actor, action, target, or correlation ID." actionLabel="Clear search" actionHref={clearHref} icon="search" />
    {:else if range !== 'all'}
      <EmptyState title="No events in this range." description="Choose a longer range to inspect older audit records." actionLabel="Show all time" actionHref={allHref} icon="clock" />
    {:else}
      <EmptyState title="No audit events recorded." description="Authentication, reviews, worker leases, builds, signatures, promotions, and rollbacks will appear here as the pipeline runs." icon="log" />
    {/if}

    <section class="section section--tight" style="padding-inline: 0" aria-labelledby="audit-rules-title"><div class="surface-grid"><article class="surface-panel"><div class="surface-panel__top"><h2 id="audit-rules-title">What is recorded</h2><Icon name="file" size={20} /></div><p>Request changes, source resolution, agent tools, generated diffs, approvals, verification, leases, builds, attestations, signing, publication, demotions, and rollbacks.</p></article><article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>What is redacted</h2><Icon name="shield" size={20} /></div><p>OAuth secrets, Cloudflare tokens, signing material, private source credentials, and unnecessary source content never enter browser payloads or audit details.</p></article></div></section>
  </section>
</MaintainerShell>
