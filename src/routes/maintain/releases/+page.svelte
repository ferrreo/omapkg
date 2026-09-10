<script lang="ts">
  import { enhance } from '$app/forms';
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

  let candidateDraft = '';

  let preparedOutput = '';

  let candidateBusy = false;

  $: releases = (Array.isArray(data?.releases) ? data.releases : []) as Release[];
  $: builds = (Array.isArray(data?.builds) ? data.builds : []) as Array<Build & { cohort_id?: string | null }>;

  type CrashQuarantine = { release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null };

  $: crashQuarantines = (Array.isArray(data?.crashQuarantines) ? data.crashQuarantines : []) as CrashQuarantine[];
  $: user = data?.user || null;
  $: isAdmin = data?.role === 'admin';
  $: devReleases = releases.filter((release) => release.channel === 'dev');
  $: stableReleases = releases.filter((release) => release.channel === 'stable');

  type Candidate = { id: string; phase: string; condition: string; current_revision: number; updated_at: number; title: string; lane: 'system' | 'opr'; manifest_json: string; manifest_sha256: string; systemVersion: string | null; compatibleSystems: string[] };

  $: candidates = (Array.isArray(data?.candidates) ? data.candidates : []) as Candidate[];
  $: systemCandidates = candidates.filter((candidate) => candidate.lane === 'system');
  $: oprCandidates = candidates.filter((candidate) => candidate.lane === 'opr');
  $: releaseTeam = data?.releaseTeam === true;
  $: distributionCandidates = (Array.isArray(data?.distributionCandidates) ? data.distributionCandidates : []) as ReleaseView[];

  let selectedReleaseIds: string[] = [];

  let promotionReason = '';

  $: selectedReleaseIdList = selectedReleaseIds.join(',');
  $: canPromote = releaseTeam && selectedReleaseIds.length > 0 && promotionReason.trim().length > 0;
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string; preparation?: unknown; repositories?: unknown } : {};

  $: if (result.preparation) preparedOutput = JSON.stringify({ preparation: result.preparation, repositories: result.repositories }, null, 2);

  const candidateEnhance = () => {
    candidateBusy = true;

    return async ({ update }: { update: (options?: { reset?: boolean }) => Promise<void> }) => {
      await update({ reset: false });
      candidateBusy = false;
    };
  };

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }
</script>

<svelte:head><title>Releases · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="releases" {user}>
  <section class="maintainer-page" aria-labelledby="releases-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Dev quarantine · compatible batches · immutable history</span><h1 id="releases-title">OPR package batches</h1><p>Existing OPR releases use package quarantine and compatible batch promotion. Cohort-managed builds stay grouped until their own release gates pass.</p><a href="/maintain/cohorts">Open system and OPR cohorts</a></div><span class="tag tag--warning"><Icon name="clock" size={13} />manual promotion</span></header>

    {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success}<div class="notice-bar" role="status"><p>Release action recorded. The resulting state and reason are in the audit log.</p><a href="/maintain/audit">Open audit<Icon name="arrow" size={14} /></a></div>{/if}

    <section class="release-lanes" aria-labelledby="release-lanes-title">
      <div class="workbench-panel release-lane-panel"><div class="workbench-panel__head"><div><p class="eyebrow">Versioned lanes</p><h2 id="release-lanes-title">System and independent OPR releases</h2></div><span class:tag--positive={releaseTeam} class="tag">{releaseTeam ? 'release team access' : 'release team membership required'}</span></div>
        <p class="prose">System candidates carry an Omarchy version such as <strong>4.0.3</strong> and move through edge, RC, and stable. OPR candidates keep package versions and compatibility snapshots independent. Admission, build completion, or recipe approval never publishes a release.</p>
        <div class="release-lane-grid">
          <article><h3>System candidates</h3>{#if systemCandidates.length}<ul>{#each systemCandidates as candidate}<li><a href={`/maintain/cohorts/${encodeURIComponent(candidate.id)}`}><strong>{candidate.systemVersion ?? 'System version not recorded'}</strong></a><StatusPill status={candidate.phase} label={`${candidate.phase} · ${candidate.condition}`} /><span class="timestamp">revision {candidate.current_revision} · {formatDate(candidate.updated_at)}</span></li>{/each}</ul>{:else}<p>No system candidate is ready in this projection. A missing candidate is not an installable release.</p>{/if}</article>
          <article><h3>OPR candidates</h3>{#if oprCandidates.length}<ul>{#each oprCandidates as candidate}<li><a href={`/maintain/cohorts/${encodeURIComponent(candidate.id)}`}><strong>{candidate.title}</strong></a><StatusPill status={candidate.phase} label={`${candidate.phase} · ${candidate.condition}`} /><span class="timestamp">{candidate.compatibleSystems.length ? `Compatible systems: ${candidate.compatibleSystems.join(', ')}` : 'System snapshot not selected'}</span></li>{/each}</ul>{:else}<p>No independent OPR cohort is ready in this projection. Package promotion below remains the legacy OPR path.</p>{/if}</article>
        </div>
      </div>
      <div class="workbench-panel release-authority-panel"><h2>Release authority</h2><p>Publication controls are scoped to the release team and rechecked against the exact candidate, target evidence, changelog digest, and current sequence at submission.</p>{#if releaseTeam}<p class="form-notice">You have release-team membership. A stale revision, missing architecture result, unapproved changelog, or concurrent publication keeps candidate state unchanged and requires a fresh review.</p>{:else}<p class="form-notice form-notice--danger">No release-team membership is present for this session. Package, administrator, or security access does not grant system/OPR publication authority.</p>{/if}<ul class="release-authority-list"><li><strong>System action:</strong> freeze or publish only from a reviewed system candidate.</li><li><strong>OPR action:</strong> publish a package/cohort with exact compatible system snapshots.</li><li><strong>Race result:</strong> refresh and review when the candidate sequence or manifest changed; no optimistic “Published” state.</li></ul></div>
    </section>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="owned-repositories-title">
      <div class="workbench-panel__head"><div><p class="eyebrow">Draft staging</p><h2 id="owned-repositories-title">Prepare owned repository refs</h2></div><span class="tag">Before final qualification</span></div>
      <p class="prose">Build exact named repository databases, package chunks, and universe roots from selected current cohorts. Preparation records bytes and evidence; it does not approve or publish a release.</p>
      <form class="review-form" method="POST" action="?/prepareRepositories" use:enhance={candidateEnhance}>
        <div class="field"><label for="owned-repository-lane">Lane</label><select id="owned-repository-lane" name="lane"><option value="system">System</option><option value="opr">Independent OPR</option></select></div>
        <div class="field"><label for="owned-repository-release">Release identity</label><input id="owned-repository-release" name="release_id" required placeholder="4.0.3-rc1 or opr-20260910-1" /></div>
        <div class="field"><label for="owned-repository-cohorts">Cohort IDs</label><input id="owned-repository-cohorts" name="cohort_ids" required placeholder="cohort-a,cohort-b" /><span class="field-help">Use current reviewed cohort IDs. Preparation fails closed when native outputs or ownership changed.</span></div>
        <div class="field"><label for="owned-repository-parent">Trusted parent release (optional)</label><input id="owned-repository-parent" name="trusted_parent_release_id" placeholder="Previous complete release" /></div>
        <button class="button button--primary" type="submit" disabled={candidateBusy}><Icon name="archive" size={14} />Prepare repository refs</button>
      </form>
      <div class="release-candidate-staging">
        <h3>Prepare release candidate</h3>
        <p>Paste exact candidate JSON. When repository preparation succeeded above, candidate JSON may omit <code>repositories</code>, <code>packageChunks</code>, <code>packageCount</code>, and <code>architectures</code>; server fills those fields from this immutable preparation and rechecks every reference.</p>
        <form class="review-form" method="POST" action="?/prepareCandidate" use:enhance={candidateEnhance}>
          <div class="field field--full"><label for="distribution-candidate-json">Candidate JSON</label><textarea id="distribution-candidate-json" name="candidate_json" rows="14" maxlength="4194304" required bind:value={candidateDraft} placeholder="Paste release kind, channel, identity, compatibility, and changelog JSON"></textarea></div>
          <input type="hidden" name="prepared_json" value={preparedOutput} />
          <button class="button button--primary" type="submit" disabled={candidateBusy || !candidateDraft.trim()}><Icon name="check" size={14} />{candidateBusy ? 'Preparing candidate…' : 'Prepare exact release candidate'}</button>
        </form>
        {#if preparedOutput}<details><summary>Exact prepared repository output</summary><pre class="code-block">{preparedOutput}</pre></details>{/if}
      </div>
    </section>

    {#if distributionCandidates.length}<section class="workbench-panel distribution-candidates" aria-labelledby="distribution-candidates-title"><div class="workbench-panel__head"><div><p class="eyebrow">Versioned release engine</p><h2 id="distribution-candidates-title">Candidate review queue</h2></div><span class="timestamp">{distributionCandidates.length} immutable candidate record{distributionCandidates.length === 1 ? '' : 's'}</span></div><p class="prose">These records come from the distribution manifest table. Candidate, signature, activation, and parent state stay separate; a package admission or completed build cannot activate one.</p><div class="distribution-candidates__list">{#each distributionCandidates as candidate}<article><header><div><p class="eyebrow">{candidate.kind === 'system' ? 'System release' : candidate.kind === 'opr' ? 'Independent OPR' : 'Resolved transaction'}</p><h3>{candidate.identity.version ?? candidate.identity.generation ?? candidate.id}</h3></div><StatusPill status={candidate.status} label={`${candidate.status} · sequence ${candidate.sequence}`} /></header><p>{candidate.summary}</p><p class="timestamp">Phase {candidate.phase}{candidate.condition ? ` · ${candidate.condition}` : ''} · manifest evidence is retained in the candidate record.</p>{#if candidate.blockers.length}<ul class="blocker-list">{#each candidate.blockers as blocker}<li><strong>{blocker.code}{blocker.architecture ? ` · ${blocker.architecture}` : ''}:</strong> {blocker.reason}{#if blocker.owner} <span class="timestamp">Owner: {blocker.owner}</span>{/if}</li>{/each}</ul>{:else}<p class="form-notice">No view-level blocker is present. Server still rechecks approvals, signatures, compatible snapshots, and the activation parent before any release action.</p>{/if}<p class="hash">Candidate {candidate.candidateId ?? candidate.id} · manifest {candidate.manifestDigest ?? 'not recorded'}</p><DistributionReleaseActions candidate={candidate} {releaseTeam} /></article>{/each}</div></section>{/if}

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
  .release-lanes { display: grid; gap: var(--space-xl); margin-bottom: var(--space-xl); }
  .release-lane-panel, .release-authority-panel { display: grid; gap: var(--space-lg); }
  .release-lane-grid { display: grid; gap: var(--space-lg); grid-template-columns: repeat(auto-fit, minmax(min(100%, 20rem), 1fr)); }
  .release-lane-grid article { border-top: var(--border-width) solid var(--color-rule); display: grid; gap: var(--space-sm); min-width: 0; padding-top: var(--space-md); }
  .release-lane-grid ul { display: grid; gap: var(--space-sm); }
  .release-lane-grid li { align-items: baseline; display: flex; flex-wrap: wrap; gap: var(--space-sm); min-width: 0; }
  .release-lane-grid li a { flex: 1 1 12rem; min-width: 0; overflow-wrap: anywhere; }
  .release-lane-grid article > p { color: var(--color-text); font-family: var(--font-body); }
  .release-authority-list { display: grid; gap: var(--space-sm); }
  .release-authority-list li { border-top: var(--border-width) solid var(--color-rule-soft); color: var(--color-text); font-family: var(--font-body); padding-top: var(--space-sm); }
  .distribution-candidates { display: grid; gap: var(--space-lg); margin-bottom: var(--space-xl); }
  .distribution-candidates__list { display: grid; gap: var(--space-md); }
  .distribution-candidates__list article { background: var(--color-canvas-deep); border-left: .2rem solid var(--color-accent); display: grid; gap: var(--space-sm); min-width: 0; padding: var(--space-lg); }
  .distribution-candidates__list article > header { align-items: start; display: flex; flex-wrap: wrap; gap: var(--space-md); justify-content: space-between; }
  .distribution-candidates__list article > header > div { min-width: 0; }
  .distribution-candidates__list article > p { color: var(--color-text); font-family: var(--font-body); }
  .distribution-candidates .blocker-list { margin: 0; }
  .release-candidate-staging { border-top: var(--border-width) solid var(--color-rule); display: grid; gap: var(--space-md); padding-top: var(--space-lg); }
</style>
