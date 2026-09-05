<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import type { Build, Release } from '$lib/model';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  $: releases = (Array.isArray(data?.releases) ? data.releases : []) as Release[];
  $: builds = (Array.isArray(data?.builds) ? data.builds : []) as Build[];
  type CrashQuarantine = { release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null };
  $: crashQuarantines = (Array.isArray(data?.crashQuarantines) ? data.crashQuarantines : []) as CrashQuarantine[];
  $: user = data?.user || null;
  $: isAdmin = data?.role === 'admin';
  $: devReleases = releases.filter((release) => release.channel === 'dev');
  $: stableReleases = releases.filter((release) => release.channel === 'stable');
  let selectedReleaseIds: string[] = [];
  let promotionReason = '';
  $: selectedReleaseIdList = selectedReleaseIds.join(',');
  $: canPromote = selectedReleaseIds.length > 0 && promotionReason.trim().length > 0;
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string } : {};

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }
</script>

<svelte:head><title>Releases · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="releases" {user}>
  <section class="maintainer-page" aria-labelledby="releases-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Dev quarantine · compatible batches · immutable history</span><h1 id="releases-title">Release batches</h1><p>Every successful build enters dev first. A maintainer promotes dependency-compatible batches to stable after tests and review.</p></div><span class="tag tag--warning"><Icon name="clock" size={13} />manual promotion</span></header>

    {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success}<div class="notice-bar" role="status"><p>Release action recorded. The resulting state and reason are in the audit log.</p><a href="/maintain/audit">Open audit<Icon name="arrow" size={14} /></a></div>{/if}

    {#if crashQuarantines.length}
      <section class="workbench-panel" aria-labelledby="quarantine-title"><div class="workbench-panel__head"><h2 id="quarantine-title">Crash quarantine</h2><span class="timestamp">{crashQuarantines.length} pending job{crashQuarantines.length === 1 ? '' : 's'}</span></div><p class="prose">Confirmed unresolved crash reports can move a stable release back to dev. Failed quarantine jobs stay here until an administrator retries them.</p><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Status</th><th>Attempts</th><th>Last error</th><th>Action</th></tr></thead><tbody>{#each crashQuarantines as job}<tr><td>{job.name}<div class="timestamp">{job.release_id}</div></td><td>{job.version}</td><td><StatusPill status={job.status} /></td><td>{job.attempts}</td><td>{job.last_error || 'No error recorded.'}</td><td>{#if job.status === 'failed' && isAdmin}<form method="POST" action="?/retryQuarantine"><input type="hidden" name="release_id" value={job.release_id} /><button class="button" type="submit"><Icon name="refresh" size={14} />Retry</button></form>{:else if job.status === 'failed'}<span class="timestamp">Administrator access required</span>{:else}<span class="timestamp">Waiting</span>{/if}</td></tr>{/each}</tbody></table></div></section>
    {/if}

    {#if devReleases.length}
      <section class="workbench-panel" aria-labelledby="promotion-title"><div class="workbench-panel__head"><h2 id="promotion-title">Development releases</h2><span class="timestamp">{selectedReleaseIds.length} selected · {devReleases.length} available</span></div><form class="release-promotion-form" method="POST" action="?/promote"><input type="hidden" name="release_ids" value={selectedReleaseIdList} /><p id="release-selection-hint" class="field__hint">Select compatible package versions to review as one batch. Eligibility is checked again on the server.</p><div class="data-table-wrap"><table class="data-table data-table--selectable"><thead><tr><th>Select</th><th>Package</th><th>Version</th><th>Arch</th><th>Published</th><th>Build evidence</th></tr></thead><tbody>{#each devReleases as release}<tr><td><label class="sr-only" for={`release-${release.id}`}>Select {release.name} {release.version} {release.architecture}</label><input id={`release-${release.id}`} class="release-selection__checkbox" type="checkbox" name="release_selection" value={release.id} bind:group={selectedReleaseIds} aria-describedby="release-selection-hint" /></td><td><strong>{release.name}</strong><div class="timestamp">{release.id}</div></td><td>{release.version}</td><td>{release.architecture}</td><td>{formatDate(release.published_at)}</td><td><a class="hash" href={`/maintain/builds/${encodeURIComponent(release.build_id)}`}>Open build</a><div class="timestamp">{release.build_id}</div></td></tr>{/each}</tbody></table></div><div class="release-promotion-form__controls"><div class="field"><label for="promote-reason">Promotion reason</label><input id="promote-reason" name="reason" bind:value={promotionReason} required placeholder="Tests, quarantine, and dependency checks reviewed" /></div><button class="button button--primary" type="submit" disabled={!canPromote}><Icon name="check" size={14} />Promote {selectedReleaseIds.length || ''} release{selectedReleaseIds.length === 1 ? '' : 's'}</button></div></form></section>
    {:else}
      <EmptyState title="No dev releases ready." description="Successful, signed builds appear here after their quarantine record is created." icon="clock" />
    {/if}

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="builds-title"><div class="workbench-panel__head"><h2 id="builds-title">Builds awaiting publication</h2><span class="timestamp">publish to dev</span></div>{#if builds.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Build</th><th>Revision</th><th>Architecture</th><th>Status</th><th>Action</th></tr></thead><tbody>{#each builds as build}<tr><td class="hash"><a href={`/maintain/builds/${encodeURIComponent(build.id)}`}>{build.id}</a></td><td class="hash">{build.revision_id}</td><td>{build.architecture}</td><td><StatusPill status={build.status} /></td><td>{#if build.status === 'succeeded'}<form method="POST" action="?/publish"><input type="hidden" name="build_id" value={build.id} /><button class="button" type="submit"><Icon name="upload" size={14} />Publish to dev</button></form>{:else}<span class="timestamp">publish after success</span>{/if}</td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No build artifacts awaiting publication." description="Worker results appear once an attested build completes." icon="upload" />{/if}</section>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="stable-title"><div class="workbench-panel__head"><h2 id="stable-title">Stable history</h2><span class="timestamp">Withdrawn releases keep their records</span></div>{#if stableReleases.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Stable since</th><th>Action</th></tr></thead><tbody>{#each stableReleases as release}<tr><td>{release.name}<div class="timestamp">{release.id}</div></td><td>{release.version}</td><td>{release.architecture}</td><td>{formatDate(release.stable_at)}</td><td><form method="POST" action="?/rollback"><input type="hidden" name="release_id" value={release.id} /><input name="reason" required placeholder="Rollback reason" aria-label={`Rollback reason for ${release.name}`} /><button class="button" type="submit"><Icon name="refresh" size={14} />Rollback</button></form></td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No stable releases yet." description="Stable history remains addressable after a maintainer promotes a dev batch." icon="archive" />{/if}</section>

    <section class="section section--tight" style="padding-inline: 0" aria-labelledby="release-gates-title"><div class="surface-grid"><article class="surface-panel"><div class="surface-panel__top"><h2 id="release-gates-title">Promotion gates</h2><Icon name="shield" size={20} /></div><p>Quarantine time, smoke tests, crash evidence, dependency readiness, a compatible batch, and a maintainer decision all remain visible before stable.</p></article><article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>Recovery</h2><Icon name="refresh" size={20} /></div><p>Rollback changes the stable index and keeps the withdrawn version in immutable storage so a compatible previous release can be selected.</p></article></div></section>
  </section>
</MaintainerShell>
