<script lang="ts">
  import { enhance } from '$app/forms';
  import type { SubmitFunction } from '@sveltejs/kit';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import DistributionReleaseActions from '$lib/components/DistributionReleaseActions.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import type { Build, Release } from '$lib/model';
  import type { ReleaseView } from '$lib/release-workbench';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;

  export let form: ActionData;

  let candidateBusy = false;
  let releaseLane: 'system' | 'opr' = 'system';
  let releaseChannel = 'edge';
  let systemDigest = data.systems[0]?.manifest_sha256 ?? '';
  let selectedChanges: string[] = [];
  let reviewing = false;

  $: releases = (Array.isArray(data?.releases) ? data.releases : []) as Release[];
  $: builds = (Array.isArray(data?.builds) ? data.builds : []) as Array<Build & { cohort_id?: string | null }>;

  type CrashQuarantine = { release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null };

  $: crashQuarantines = (Array.isArray(data?.crashQuarantines) ? data.crashQuarantines : []) as CrashQuarantine[];
  $: user = data?.user || null;
  $: isAdmin = data?.role === 'admin';
  $: devReleases = releases.filter((release) => release.channel === 'dev');
  $: stableReleases = releases.filter((release) => release.channel === 'stable');

  type Candidate = { id: string; phase: string; condition: string; current_revision: number; updated_at: number; title: string; lane: 'system' | 'opr'; manifest_json: string; manifest_sha256: string; systemVersion: string | null; compatibleSystems: string[]; opr_count: number };

  $: candidates = (Array.isArray(data?.candidates) ? data.candidates : []) as Candidate[];
  $: availableChanges = candidates.filter((candidate) => releaseLane === 'system' ? candidate.lane === 'system' : candidate.lane === 'opr' || candidate.opr_count > 0);
  $: selectedCohorts = availableChanges.filter((candidate) => selectedChanges.includes(`${candidate.id}@${candidate.manifest_sha256}`));
  $: selectedVersions = [...new Set(selectedCohorts.map((candidate) => candidate.systemVersion))];
  $: canPrepare = selectedCohorts.length > 0 && (releaseLane === 'system' ? selectedVersions.length === 1 && Boolean(selectedVersions[0]) : Boolean(systemDigest));
  $: releaseTeam = data?.releaseTeam === true;
  $: distributionCandidates = (Array.isArray(data?.distributionCandidates) ? data.distributionCandidates : []) as ReleaseView[];

  let selectedReleaseIds: string[] = [];

  let promotionReason = '';

  $: selectedReleaseIdList = selectedReleaseIds.join(',');
  $: canPromote = releaseTeam && selectedReleaseIds.length > 0 && promotionReason.trim().length > 0;
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string; message?: string; nextChanges?: Array<{ id: string; title: string }> } : {};

  function chooseLane(lane: 'system' | 'opr') {
    releaseLane = lane;
    releaseChannel = lane === 'system' ? 'edge' : 'quarantine';
    selectedChanges = [];
    reviewing = false;
  }

  const candidateEnhance: SubmitFunction = () => {
    candidateBusy = true;

    return async ({ result: outcome, update }) => {
      try {
        await update({ reset: false });
        if (outcome.type === 'success') { reviewing = false; selectedChanges = []; }
      } finally { candidateBusy = false; }
    };
  };

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }
</script>

<svelte:head><title>Releases · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="releases" {user}>
  <section class="maintainer-page" aria-labelledby="releases-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Review and publish</span><h1 id="releases-title">Releases</h1><p>Prepare system and app updates, review their checks, and publish when ready.</p><a href="/maintain/cohorts">View change sets</a></div><span class="tag tag--warning"><Icon name="clock" size={13} />manual promotion</span></header>

    {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success}<div class="notice-bar" role="status"><p>{result.message ?? 'Release action recorded.'}</p>{#if result.nextChanges}<ul>{#each result.nextChanges as change}<li><a href={`/maintain/cohorts/${encodeURIComponent(change.id)}`}>Continue checks: {change.title}</a></li>{/each}</ul>{:else}<a href="/maintain/audit">View activity<Icon name="arrow" size={14} /></a>{/if}</div>{/if}

    <section class="workbench-panel release-composer" aria-labelledby="prepare-release-title">
      <header><p class="eyebrow">New release</p><h2 id="prepare-release-title">Choose what to release</h2><p>Select changes, review the summary, then prepare the release. Repository files and release notes are assembled automatically.</p></header>
      <form method="POST" action="?/prepareRelease" use:enhance={candidateEnhance}>
        <fieldset class="release-type" disabled={candidateBusy}>
          <legend>What are you updating?</legend>
          <label><input type="radio" name="lane" value="system" bind:group={releaseLane} on:change={() => chooseLane('system')} /><span><strong>System update</strong><small>Release a new operating-system version.</small></span></label>
          <label><input type="radio" name="lane" value="opr" bind:group={releaseLane} on:change={() => chooseLane('opr')} /><span><strong>App updates</strong><small>Release OPR packages independently.</small></span></label>
        </fieldset>
        <div class="release-settings">
          <div class="field"><label for="release-channel">Who is this for?</label><select id="release-channel" name="channel" bind:value={releaseChannel} on:change={() => reviewing = false} disabled={candidateBusy}>{#if releaseLane === 'system'}<option value="edge">Early testing</option><option value="rc">Release-candidate testing</option>{:else}<option value="quarantine">Testing</option>{/if}<option value="stable">Everyone · stable</option></select></div>
          {#if releaseLane === 'opr'}<div class="field"><label for="release-system">Compatible system</label><select id="release-system" name="system" bind:value={systemDigest} on:change={() => reviewing = false} disabled={candidateBusy || !data.systems.length}>{#if !data.systems.length}<option value="">No tested system release available</option>{/if}{#each data.systems as system}<option value={system.manifest_sha256}>{system.release_id} · {system.channel}</option>{/each}</select>{#if !data.systems.length}<span class="field-help">Prepare and test a system release before releasing app updates.</span>{/if}</div>{/if}
        </div>
        <fieldset class="release-changes" disabled={candidateBusy}>
          <legend>Changes to include</legend>
          {#if availableChanges.length}
            {#each availableChanges as change}
              <div class="release-change">
                <label><input type="checkbox" name="changes" value={`${change.id}@${change.manifest_sha256}`} bind:group={selectedChanges} on:change={() => reviewing = false} disabled={change.condition === 'held' || !['verify', 'stage', 'approve', 'publish', 'observe'].includes(change.phase)} /><span><strong>{change.title}</strong><small>{change.systemVersion ? `Version ${change.systemVersion} · ` : ''}{change.condition === 'held' ? 'On hold' : ['approve', 'publish', 'observe'].includes(change.phase) && change.condition === 'ready' ? 'Checks complete' : change.phase === 'stage' ? 'Review pending' : change.phase === 'verify' ? 'Final checks pending' : 'Finish builds first'}</small></span></label>
                <a href={`/maintain/cohorts/${encodeURIComponent(change.id)}`}>View changes<Icon name="arrow" size={13} /></a>
              </div>
            {/each}
          {:else}
            <div class="release-empty"><strong>No changes available yet</strong><p>Completed builds appear here as change sets. Start there, then return to prepare a release.</p><a class="button" href="/maintain/cohorts">View change sets<Icon name="arrow" size={14} /></a></div>
          {/if}
        </fieldset>
        {#if availableChanges.length}
          {#if releaseLane === 'system' && selectedCohorts.length && (selectedVersions.length !== 1 || !selectedVersions[0])}<p class="field__hint field__hint--danger" role="status">Select changes planned for the same system version. You can set the version on the change-set page.</p>{/if}
          {#if reviewing}
            <section class="release-summary" aria-labelledby="release-summary-title" aria-live="polite">
              <p class="eyebrow">Review</p><h3 id="release-summary-title">{releaseLane === 'system' ? `System ${selectedVersions[0]}` : 'App updates'}</h3>
              <p>{releaseChannel === 'stable' ? 'For everyone on the stable channel.' : releaseChannel === 'rc' ? 'For release-candidate testing.' : 'For testing before wider release.'}</p>
              <ul>{#each selectedCohorts as change}<li>{change.title}</li>{/each}</ul>
              <p>Prepare the release files and check required reviews. Publication needs a separate approval.</p>
              <div class="release-controls"><button class="button" type="button" on:click={() => reviewing = false} disabled={candidateBusy}>Back</button><button class="button button--primary" type="submit" disabled={candidateBusy || !canPrepare}>{candidateBusy ? 'Preparing release…' : 'Prepare release'}<Icon name="arrow" size={14} /></button></div>
            </section>
          {:else}<div class="release-controls"><span>{selectedCohorts.length} change set{selectedCohorts.length === 1 ? '' : 's'} selected</span><button class="button button--primary" type="button" on:click={() => reviewing = true} disabled={!canPrepare}>Review release<Icon name="arrow" size={14} /></button></div>{/if}
        {/if}
      </form>
    </section>

    {#if distributionCandidates.length}<section class="workbench-panel distribution-candidates" aria-labelledby="distribution-candidates-title"><div class="workbench-panel__head"><div><p class="eyebrow">Next step</p><h2 id="distribution-candidates-title">Releases to review</h2></div><span class="timestamp">{distributionCandidates.length} immutable candidate record{distributionCandidates.length === 1 ? '' : 's'}</span></div><p class="prose">Review the checks and release notes before publishing.</p><div class="distribution-candidates__list">{#each distributionCandidates as candidate}<article><header><div><p class="eyebrow">{candidate.kind === 'system' ? 'System release' : candidate.kind === 'opr' ? 'Independent OPR' : 'Resolved transaction'}</p><h3>{candidate.identity.version ?? candidate.identity.generation ?? candidate.id}</h3></div><StatusPill status={candidate.status} label={`${candidate.status} · sequence ${candidate.sequence}`} /></header><p>{candidate.summary}</p><p class="timestamp">Phase {candidate.phase}{candidate.condition ? ` · ${candidate.condition}` : ''} · manifest evidence is retained in the candidate record.</p>{#if candidate.blockers.length}<ul class="blocker-list">{#each candidate.blockers as blocker}<li><strong>{blocker.code}{blocker.architecture ? ` · ${blocker.architecture}` : ''}:</strong> {blocker.reason}{#if blocker.owner} <span class="timestamp">Owner: {blocker.owner}</span>{/if}</li>{/each}</ul>{:else}<p class="form-notice">Checks complete. This release is ready for the next action.</p>{/if}<details><summary>Release identifiers</summary><p class="hash">Candidate {candidate.candidateId ?? candidate.id} · manifest {candidate.manifestDigest ?? 'not recorded'}</p></details><DistributionReleaseActions candidate={candidate} {releaseTeam} /></article>{/each}</div></section>{/if}

    {#if crashQuarantines.length}
      <section class="workbench-panel" aria-labelledby="quarantine-title"><div class="workbench-panel__head"><h2 id="quarantine-title">Crash quarantine</h2><span class="timestamp">{crashQuarantines.length} pending job{crashQuarantines.length === 1 ? '' : 's'}</span></div><p class="prose">Confirmed unresolved crash reports can move a stable release back to dev. Failed quarantine jobs stay here until an administrator retries them.</p><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Status</th><th>Attempts</th><th>Last error</th><th>Action</th></tr></thead><tbody>{#each crashQuarantines as job}<tr><td>{job.name}<div class="timestamp">{job.release_id}</div></td><td>{job.version}</td><td><StatusPill status={job.status} /></td><td>{job.attempts}</td><td>{job.last_error || 'No error recorded.'}</td><td>{#if job.status === 'failed' && isAdmin}<form method="POST" action="?/retryQuarantine"><input type="hidden" name="release_id" value={job.release_id} /><button class="button" type="submit"><Icon name="refresh" size={14} />Retry</button></form>{:else if job.status === 'failed'}<span class="timestamp">Administrator access required</span>{:else}<span class="timestamp">Waiting</span>{/if}</td></tr>{/each}</tbody></table></div></section>
    {/if}

    {#if devReleases.length}
      <section class="workbench-panel" aria-labelledby="promotion-title"><div class="workbench-panel__head"><h2 id="promotion-title">Development releases</h2><span class="timestamp">{selectedReleaseIds.length} selected · {devReleases.length} available</span></div><form class="release-promotion-form" method="POST" action="?/promote"><input type="hidden" name="release_ids" value={selectedReleaseIdList} /><p id="release-selection-hint" class="field__hint">Select compatible package versions to review as one batch. Eligibility is checked again on the server.</p><div class="data-table-wrap"><table class="data-table data-table--selectable"><thead><tr><th>Select</th><th>Package</th><th>Version</th><th>Arch</th><th>Published</th><th>Build evidence</th></tr></thead><tbody>{#each devReleases as release}<tr><td><label class="sr-only" for={`release-${release.id}`}>Select {release.name} {release.version} {release.architecture}</label><input id={`release-${release.id}`} class="release-selection__checkbox" type="checkbox" name="release_selection" value={release.id} bind:group={selectedReleaseIds} aria-describedby="release-selection-hint" /></td><td><strong>{release.name}</strong><div class="timestamp">{release.id}</div></td><td>{release.version}</td><td>{release.architecture}</td><td>{formatDate(release.published_at)}</td><td><a class="hash" href={`/maintain/builds/${encodeURIComponent(release.build_id)}`}>Open build</a><div class="timestamp">{release.build_id}</div></td></tr>{/each}</tbody></table></div><div class="release-promotion-form__controls"><div class="field"><label for="promote-reason">Promotion reason</label><input id="promote-reason" name="reason" bind:value={promotionReason} required placeholder="Tests, quarantine, and dependency checks reviewed" /></div><button class="button button--primary" type="submit" disabled={!canPromote}><Icon name="check" size={14} />Promote {selectedReleaseIds.length || ''} release{selectedReleaseIds.length === 1 ? '' : 's'}</button></div>{#if !releaseTeam}<p class="field__hint field__hint--danger">Explicit release-team membership is required for stable promotion. Review access alone cannot bypass this gate.</p>{/if}</form></section>
    {:else}
      <EmptyState title="No dev releases ready." description="Successful, signed builds appear here after their quarantine record is created." icon="clock" />
    {/if}

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="builds-title"><div class="workbench-panel__head"><h2 id="builds-title">Builds awaiting publication</h2><span class="timestamp">publish to dev</span></div>{#if builds.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Build</th><th>Revision</th><th>Architecture</th><th>Status</th><th>Action</th></tr></thead><tbody>{#each builds as build}<tr><td class="hash"><a href={`/maintain/builds/${encodeURIComponent(build.id)}`}>{build.id}</a></td><td class="hash">{build.revision_id}</td><td>{build.architecture}</td><td><StatusPill status={build.status} /></td><td>{#if build.cohort_id}<a href={`/maintain/cohorts/${encodeURIComponent(build.cohort_id)}`}>Open coordinated cohort</a>{:else if build.status === 'succeeded'}<form method="POST" action="?/publish"><input type="hidden" name="build_id" value={build.id} /><button class="button" type="submit"><Icon name="upload" size={14} />Publish to dev</button></form>{:else}<span class="timestamp">publish after success</span>{/if}</td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No build artifacts awaiting publication." description="Worker results appear once an attested build completes." icon="upload" />{/if}</section>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="stable-title"><div class="workbench-panel__head"><h2 id="stable-title">Stable history</h2><span class="timestamp">Withdrawn releases keep their records</span></div>{#if stableReleases.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Stable since</th><th>Action</th></tr></thead><tbody>{#each stableReleases as release}<tr><td>{release.name}<div class="timestamp">{release.id}</div></td><td>{release.version}</td><td>{release.architecture}</td><td>{formatDate(release.stable_at)}</td><td><form method="POST" action="?/rollback"><input type="hidden" name="release_id" value={release.id} /><input name="reason" required placeholder="Rollback reason" aria-label={`Rollback reason for ${release.name}`} /><button class="button" type="submit"><Icon name="refresh" size={14} />Rollback</button></form></td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No stable releases yet." description="Stable history remains addressable after a maintainer promotes a dev batch." icon="archive" />{/if}</section>

    <section class="section section--tight" style="padding-inline: 0" aria-labelledby="release-gates-title"><div class="surface-grid"><article class="surface-panel"><div class="surface-panel__top"><h2 id="release-gates-title">Promotion gates</h2><Icon name="shield" size={20} /></div><p>Quarantine time, smoke tests, crash evidence, dependency readiness, a compatible batch, and a maintainer decision all remain visible before stable.</p></article><article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>Recovery</h2><Icon name="refresh" size={20} /></div><p>Rollback changes the stable index and keeps the withdrawn version in immutable storage so a compatible previous release can be selected.</p></article></div></section>
  </section>
</MaintainerShell>

<style>
  /* Hallmark · pre-emit critique: P4 H4 E4 S5 R5 V4 · existing Omarchy tokens · release task flow */
  .maintainer-page__head { margin-bottom: var(--space-lg); }
  #releases-title { font-size: var(--text-2xl); }
  #prepare-release-title { font-size: var(--text-xl); }
  .release-composer { display: grid; gap: var(--space-lg); margin-bottom: var(--space-xl); font-family: var(--font-body); }
  .release-composer header { display: grid; gap: var(--space-sm); max-width: 48rem; }
  .release-composer form { display: grid; gap: var(--space-lg); }
  .release-composer fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
  .release-composer legend { font-weight: 600; margin-bottom: var(--space-sm); }
  .release-type { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-md); }
  .release-type label { border: var(--border-width) solid var(--color-rule); border-radius: var(--radius-sm); display: flex; align-items: start; gap: var(--space-sm); padding: var(--space-md); cursor: pointer; }
  .release-type label:has(input:checked) { border-color: var(--color-accent); background: var(--color-canvas-deep); }
  .release-type input, .release-change input { accent-color: var(--color-accent); flex: none; margin-top: .25rem; }
  .release-type span, .release-change span { display: grid; gap: var(--space-xs); min-width: 0; }
  .release-composer small { color: var(--color-text-muted); font-size: var(--text-sm); }
  .release-settings { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 19rem), 1fr)); gap: var(--space-md); }
  .release-settings select { font-family: inherit; }
  .release-change { display: flex; align-items: center; justify-content: space-between; gap: var(--space-md); padding: var(--space-md) 0; border-top: var(--border-width) solid var(--color-rule-soft); }
  .release-change label { display: flex; align-items: start; gap: var(--space-sm); min-width: 0; cursor: pointer; }
  .release-change label:has(input:disabled) { cursor: default; color: var(--color-text-muted); }
  .release-change strong { overflow-wrap: anywhere; }
  .release-change a { display: inline-flex; align-items: center; gap: var(--space-xs); white-space: nowrap; flex: none; }
  .release-empty, .release-summary { display: grid; gap: var(--space-md); background: var(--color-canvas-deep); padding: var(--space-lg); }
  .release-empty .button { justify-self: start; }
  .release-summary ul { padding-left: var(--space-lg); list-style: disc; }
  .release-controls { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: var(--space-md); }
  .release-controls > span { margin-right: auto; color: var(--color-text-muted); }
  .release-controls .button { white-space: nowrap; }
  @media (max-width: 600px) { .release-type { grid-template-columns: minmax(0, 1fr); } .release-change { align-items: start; flex-direction: column; } }
  .distribution-candidates { display: grid; gap: var(--space-lg); margin-bottom: var(--space-xl); }
  .distribution-candidates__list { display: grid; gap: var(--space-md); }
  .distribution-candidates__list article { background: var(--color-canvas-deep); border-left: .2rem solid var(--color-accent); display: grid; gap: var(--space-sm); min-width: 0; padding: var(--space-lg); }
  .distribution-candidates__list article > header { align-items: start; display: flex; flex-wrap: wrap; gap: var(--space-md); justify-content: space-between; }
  .distribution-candidates__list article > header > div { min-width: 0; }
  .distribution-candidates__list article > p { color: var(--color-text); font-family: var(--font-body); }
  .distribution-candidates .blocker-list { margin: 0; }
</style>
