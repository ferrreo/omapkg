<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import GitHubSignIn from '$lib/components/GitHubSignIn.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import { CRASH_CONSENT_VERSION } from '$lib/reports';
  import type { PageData } from './$types';

  export let data: PageData;

  type DetailRelease = PageData['releases'][number];
  $: releases = data.releases;
  $: revisions = data.revisions;
  $: request = data.request;
  $: channel = data.channel;
  $: architecture = data.architecture;
  $: architectureOptions = data.architectures;
  $: latest = releases[0] || null;
  $: revision = revisions[0] || null;
  $: finalDescription = revision?.description || '';
  $: name = data.name || latest?.name || request?.name || 'Package';
  $: user = data.user || null;
  $: role = data.role || 'public';
  $: packages = latest ? [latest] : [];
  type FeedbackEntry = { works: number; comment: string; created_at: number };
  type CrashReport = {
    id?: string;
    release_id?: string;
    summary: string;
    created_at: number;
    resolved_at?: number | null;
    resolved_by?: string | null;
    resolved_by_name?: string | null;
    resolved_by_username?: string | null;
    confirmed_at?: number | null;
    confirmed_by?: string | null;
    confirmed_by_name?: string | null;
    confirmed_by_username?: string | null;
  };
  $: feedback = (Array.isArray(data?.feedback) ? data.feedback : []) as FeedbackEntry[];
  $: crashReports = (Array.isArray(data?.crashes) ? data.crashes : []) as CrashReport[];
  $: publicCrashReports = crashReports.filter((report) => Boolean(report.confirmed_at));
  $: actorNames = role === 'public' ? {} : ((data as unknown as { actorNames?: Record<string, string> })?.actorNames || {}) as Record<string, string>;

  let feedbackWorks = '1';
  let feedbackComment = '';
  let feedbackBusy = false;
  let feedbackError = '';
  let feedbackSuccess = '';
  let crashSummary = '';
  let crashConsent = false;
  let crashBusy = false;
  let crashError = '';
  let crashSuccess = '';
  let resolutionReasons: Record<string, string> = {};
  let resolvingReport = '';
  let triageActions: Record<string, 'confirm' | 'resolve'> = {};
  let resolutionError = '';
  let resolutionSuccess = '';
  let confirmedReports = new Set<string>();
  let confirmedAt: Record<string, number> = {};
  let confirmedBy: Record<string, string> = {};
  let resolvedReports = new Set<string>();
  let resolvedAt: Record<string, number> = {};
  let resolvedBy: Record<string, string> = {};

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 10) : '—';
  }

  function parseList(value: string | null | undefined): string[] {
    if (!value) return [];
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch {
      return [];
    }
  }

  function artifactHref(release: DetailRelease) {
    if (!release.artifact_filename || release.surface !== 'binary') return '';
    return `/repo/${release.channel === 'dev' ? 'dev/' : ''}${release.architecture}/${encodeURIComponent(release.artifact_filename)}`;
  }

  function recipeHref(release: DetailRelease) {
    return `/repo/${release.channel === 'dev' ? 'dev/' : ''}recipes/${encodeURIComponent(release.name)}/${encodeURIComponent(release.version)}/${release.architecture}/PKGBUILD`;
  }

  function metadataHref(release: DetailRelease, filename: 'sbom.json' | 'provenance.json') {
    return `/repo/metadata/${encodeURIComponent(release.id)}/${filename}`;
  }

  function sourceKindLabel(value: string | undefined) {
    return value === 'git' ? 'Git repository' : 'Download (source or binary package)';
  }

  function formatDateTime(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  function selectArchitecture(event: Event) {
    (event.currentTarget as HTMLSelectElement).form?.requestSubmit();
  }

  type ApiBody = {
    error?: string;
    accepted?: boolean;
    confirmedAt?: number;
    confirmedBy?: string;
    resolvedAt?: number;
    resolvedBy?: string;
    reviewedAt?: number;
  };

  async function responseBody(response: Response): Promise<ApiBody> {
    return await response.json().catch(() => ({})) as ApiBody;
  }

  async function submitFeedback() {
    if (!latest || feedbackBusy) return;
    feedbackBusy = true;
    feedbackError = '';
    feedbackSuccess = '';
    try {
      const response = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ releaseId: latest.id, works: feedbackWorks === '1' ? 1 : 0, comment: feedbackComment.trim() })
      });
      const body = await responseBody(response);
      if (!response.ok) throw new Error(body.error || 'Feedback could not be recorded.');
      feedbackSuccess = 'Feedback recorded for this release.';
      feedbackComment = '';
      await invalidateAll();
    } catch (cause) {
      feedbackError = cause instanceof Error ? cause.message : 'Feedback could not be recorded.';
    } finally {
      feedbackBusy = false;
    }
  }

  async function submitCrash() {
    if (!latest || crashBusy) return;
    crashBusy = true;
    crashError = '';
    crashSuccess = '';
    try {
      const response = await fetch('/api/crashes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ releaseId: latest.id, summary: crashSummary.trim(), consent: crashConsent, consentVersion: CRASH_CONSENT_VERSION })
      });
      const body = await responseBody(response);
      if (!response.ok) throw new Error(body.error || 'Crash report could not be recorded.');
      crashSuccess = 'Crash report recorded for this release.';
      crashSummary = '';
      crashConsent = false;
      await invalidateAll();
    } catch (cause) {
      crashError = cause instanceof Error ? cause.message : 'Crash report could not be recorded.';
    } finally {
      crashBusy = false;
    }
  }

  function setResolutionReason(reportId: string, value: string) {
    resolutionReasons = { ...resolutionReasons, [reportId]: value };
  }

  function setTriageAction(reportId: string, action: 'confirm' | 'resolve') {
    triageActions = { ...triageActions, [reportId]: action };
  }

  function reportActorLabel(report: CrashReport, action: 'confirmed' | 'resolved') {
    const record = report as unknown as Record<string, unknown>;
    const explicitKeys = action === 'confirmed'
      ? ['confirmed_by_username', 'confirmed_by_name']
      : ['resolved_by_username', 'resolved_by_name'];
    const explicit = explicitKeys.map((key) => record[key]).find((value): value is string => typeof value === 'string' && value.trim().length > 0);
    if (explicit) return explicit;
    const actor = action === 'confirmed'
      ? report.confirmed_by || (report.id ? confirmedBy[report.id] : '')
      : report.resolved_by || (report.id ? resolvedBy[report.id] : '');
    if (actor && actorNames[actor]) return actorNames[actor];
    if (actor && !actor.includes(':')) return actor.startsWith('@') ? actor : `@${actor}`;
    return actor ? 'Maintainer' : '';
  }

  async function triageCrash(report: CrashReport, action: 'confirm' | 'resolve') {
    if (!report.id || resolvingReport) return;
    const reason = resolutionReasons[report.id]?.trim() || '';
    if (!reason) return;
    resolvingReport = report.id;
    resolutionError = '';
    resolutionSuccess = '';
    try {
      const response = await fetch('/api/crashes', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportId: report.id, reason, action })
      });
      const body = await responseBody(response);
      if (!response.ok) throw new Error(body.error || `Crash report could not be ${action === 'confirm' ? 'confirmed' : 'resolved'}.`);
      const timestamp = action === 'confirm' ? body.confirmedAt || body.reviewedAt : body.resolvedAt || body.reviewedAt;
      const actor = action === 'confirm' ? body.confirmedBy || user?.githubUsername : body.resolvedBy || user?.githubUsername;
      const fallbackTimestamp = Math.floor(Date.now() / 1000);
      if (action === 'confirm') {
        confirmedReports = new Set([...confirmedReports, report.id]);
        confirmedAt = { ...confirmedAt, [report.id]: timestamp || fallbackTimestamp };
        if (actor) confirmedBy = { ...confirmedBy, [report.id]: actor };
      } else {
        resolvedReports = new Set([...resolvedReports, report.id]);
        resolvedAt = { ...resolvedAt, [report.id]: timestamp || fallbackTimestamp };
        if (actor) resolvedBy = { ...resolvedBy, [report.id]: actor };
      }
      resolutionReasons = { ...resolutionReasons, [report.id]: '' };
      resolutionSuccess = action === 'confirm' ? `Crash report ${report.id} marked reviewed.` : `Crash report ${report.id} marked resolved.`;
    } catch (cause) {
      resolutionError = cause instanceof Error ? cause.message : `Crash report could not be ${action === 'confirm' ? 'confirmed' : 'resolved'}.`;
    } finally {
      resolvingReport = '';
    }
  }
</script>

<svelte:head>
  <title>{name} · omapkg</title>
  <meta name="description" content={`Public package evidence for ${name}.`} />
</svelte:head>

<PublicNav {user} {role} packages={packages} />

<main class="public-main">
  {#if latest || request}
    <section class="section site-width--narrow" aria-labelledby="package-title">
      <div class="section__head">
        <div>
          <h1 id="package-title">{name}</h1>
          {#if finalDescription}<p class="prose">{finalDescription}</p>{:else}<p class="prose">A release record with source, review, build, and distribution evidence.</p>{/if}
        </div>
        <div class="package-header__actions">
          <form class="package-selector" method="GET" aria-label="Select package architecture">
            <input type="hidden" name="channel" value={channel} />
            <label for="package-architecture">Architecture</label>
            <select id="package-architecture" name="architecture" bind:value={architecture} on:change={selectArchitecture}>{#each architectureOptions as option}<option value={option}>{option}</option>{/each}</select>
          </form>
          {#if latest}<StatusPill status={latest.channel} />{/if}
        </div>
      </div>

      <div class="detail-grid">
        <div class="detail-stack">
          <section aria-labelledby="release-title">
            <div class="workbench-panel__head"><h2 id="release-title">Current release</h2>{#if latest}<span class="timestamp">published {formatDate(latest.published_at)}</span>{/if}</div>
            {#if latest}
              <div class="detail-list">
                <div class="detail-list__row"><span class="detail-list__key">Version</span><span class="detail-list__value">{latest.version}</span></div>
                <div class="detail-list__row"><span class="detail-list__key">Surface</span><span class="detail-list__value">{latest.surface === 'binary' ? 'Surface A · signed binary' : 'Surface B · recipe'}</span></div>
                <div class="detail-list__row"><span class="detail-list__key">Architecture</span><span class="detail-list__value">{latest.architecture}</span></div>
                <div class="detail-list__row"><span class="detail-list__key">Channel</span><span class="detail-list__value"><StatusPill status={latest.channel} /></span></div>
                <div class="detail-list__row"><span class="detail-list__key">Source repository</span>{#if request?.upstream_url}<a class="detail-list__value" href={request.upstream_url} rel="noreferrer">{request.upstream_url}<Icon name="external" size={14} /></a>{:else}<span class="detail-list__value">Not recorded</span>{/if}</div>
              </div>
            {:else}
              <EmptyState title="No published release yet." description="This request is visible, but a public release record is not available." actionLabel="Browse packages" actionHref="/packages" icon="clock" />
            {/if}
          </section>

          <section aria-labelledby="install-title">
            <div class="workbench-panel__head"><h2 id="install-title">Install path</h2>{#if latest}<span class="tag">{latest.surface === 'binary' ? 'pacman' : 'recipe'}</span>{/if}</div>
            {#if latest?.surface === 'binary'}
              <div class="workbench-panel">
                <p class="prose">Configure the omapkg repository keyring, then install the reviewed stable package with Arch tooling.</p>
                <div class="action-row" style="margin-top: var(--space-lg)"><pre class="code-block">sudo pacman -S {name}</pre><CopyButton value={`sudo pacman -S ${name}`} label="Copy command" /></div>
                <p class="field__hint" style="margin-top: var(--space-md)"><a href="/repo/key.asc">Download repository key</a> and verify it before adding the repository.</p>
              </div>
            {:else if latest}
              <div class="workbench-panel">
                <p class="prose">This Surface B recipe does not redistribute vendor bytes. Build it locally; the recipe fetches the pinned source URL and verifies its checksum.</p>
                <a class="button" href={recipeHref(latest)}>Open recipe<Icon name="code" size={14} /></a>
              </div>
            {:else}
              <EmptyState title="Install instructions are pending." description="A reviewed release supplies the exact command or recipe link." icon="terminal" />
            {/if}
          </section>

          <section aria-labelledby="history-title">
            <div class="workbench-panel__head"><h2 id="history-title">Release history</h2><span class="timestamp">immutable records</span></div>
            {#if releases.length}
              <div class="data-table-wrap">
                <table class="data-table">
                  <thead><tr><th>Version</th><th>Channel</th><th>Arch</th><th>Published</th><th>Evidence</th></tr></thead>
                  <tbody>
                    {#each releases as release}
                      <tr><td>{release.version}</td><td><StatusPill status={release.channel} /></td><td>{release.architecture}</td><td>{formatDate(release.published_at)}</td><td>{#if release.provenance_key}<a href={metadataHref(release, 'provenance.json')}>provenance</a>{:else}<span class="timestamp">pending</span>{/if}</td></tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <EmptyState title="No releases recorded." description="Historical versions remain addressable after publication." icon="archive" />
            {/if}
          </section>

          {#if latest}
            <section class="workbench-panel" aria-labelledby="feedback-title">
              <div class="workbench-panel__head"><h2 id="feedback-title">Release feedback</h2><span class="timestamp">{feedback.length} report{feedback.length === 1 ? '' : 's'}</span></div>
              {#if feedback.length}
                <div class="timeline">
                  {#each feedback as entry}
                    <article class="timeline__item"><strong>{entry.works === 1 ? 'Works for me' : 'Needs attention'}</strong><span class="timestamp">{formatDateTime(entry.created_at)}</span><p>{entry.comment}</p></article>
                  {/each}
                </div>
              {:else}
                <p class="field__hint">No feedback has been recorded for this release.</p>
              {/if}

              {#if user}
                <form class="form-grid" style="margin-top: var(--space-xl)" on:submit|preventDefault={submitFeedback}>
                  <div class="field">
                    <label for="feedback-works">Release result</label>
                    <select id="feedback-works" bind:value={feedbackWorks}>
                      <option value="1">It works</option>
                      <option value="0">It does not work</option>
                    </select>
                  </div>
                  <div class="field field--full">
                    <label for="feedback-comment">Comment</label>
                    <textarea id="feedback-comment" bind:value={feedbackComment} required maxlength="2000" placeholder="What happened when you installed or ran it?" aria-describedby="feedback-hint"></textarea>
                    <span id="feedback-hint" class="field__hint">Keep comments about this release. Do not include private or personal details.</span>
                  </div>
                  {#if feedbackError}<div class="form-notice form-notice--danger field--full" role="alert">{feedbackError}</div>{/if}
                  {#if feedbackSuccess}<div class="form-notice field--full" role="status">{feedbackSuccess}</div>{/if}
                  <div class="form-actions" style="grid-column: 1 / -1; margin-top: 0"><span class="field__hint">Feedback is attached to release {latest.version}.</span><button class="button button--primary" type="submit" disabled={feedbackBusy}>{feedbackBusy ? 'Recording…' : 'Record feedback'}<Icon name="arrow" size={14} /></button></div>
                </form>
              {:else}
                <div class="notice-bar" style="margin-top: var(--space-xl)"><p>Sign in with GitHub to record release feedback.</p><GitHubSignIn callbackURL={`/packages/${encodeURIComponent(name)}`} /></div>
              {/if}
            </section>

            <section class="workbench-panel" aria-labelledby="crash-report-title">
              <div class="workbench-panel__head"><h2 id="crash-report-title">Opt-in crash report</h2><span class="timestamp">anonymous</span></div>
              <p class="prose">Send one report for this release if it crashes. We collect only the release ID, your summary, and consent version. There is no automatic telemetry.</p>
              <p class="field__hint">Read the <a href="/privacy">privacy policy</a> before sharing a report. Leave out names, paths, tokens, and other personal details.</p>
              <form class="form-grid" style="margin-top: var(--space-xl)" on:submit|preventDefault={submitCrash}>
                <div class="field field--full">
                  <label for="crash-summary">What happened?</label>
                  <textarea id="crash-summary" bind:value={crashSummary} required maxlength="4000" placeholder="Short description of the crash and what you were doing" aria-describedby="crash-hint"></textarea>
                  <span id="crash-hint" class="field__hint">Do not include personal details. The report is scoped to release {latest.version}.</span>
                </div>
                <label class="consent-check field--full" for="crash-consent"><input id="crash-consent" type="checkbox" bind:checked={crashConsent} required /> <span>I consent to sending this anonymous report under <a href="/privacy">{CRASH_CONSENT_VERSION}</a>.</span></label>
                {#if crashError}<div class="form-notice form-notice--danger field--full" role="alert">{crashError}</div>{/if}
                {#if crashSuccess}<div class="form-notice field--full" role="status">{crashSuccess}</div>{/if}
                <div class="form-actions" style="grid-column: 1 / -1; margin-top: 0"><span class="field__hint">Only this submission sends data.</span><button class="button" type="submit" disabled={crashBusy}>{crashBusy ? 'Sending…' : 'Send crash report'}<Icon name="upload" size={14} /></button></div>
              </form>
            </section>
          {/if}
        </div>

        <aside class="detail-stack">
          <section class="workbench-panel" aria-labelledby="proof-title">
            <div class="workbench-panel__head"><h2 id="proof-title">Release evidence</h2><Icon name="shield" size={18} /></div>
            {#if latest}
              <div class="detail-list">
                <div class="detail-list__row"><span class="detail-list__key">Artifact</span>{#if artifactHref(latest)}<a class="detail-list__value" href={artifactHref(latest)}>Download <Icon name="download" size={14} /></a>{:else if latest.surface === 'recipe'}<a class="detail-list__value" href={recipeHref(latest)}>Open recipe <Icon name="code" size={14} /></a>{:else}<span class="detail-list__value">Pending</span>{/if}</div>
                <div class="detail-list__row"><span class="detail-list__key">Signature</span>{#if artifactHref(latest)}<a class="detail-list__value" href={`${artifactHref(latest)}.sig`}>Open signature</a>{:else}<span class="detail-list__value">{latest.surface === 'recipe' ? 'Not applicable' : 'Pending'}</span>{/if}</div>
                <div class="detail-list__row"><span class="detail-list__key">SBOM</span>{#if latest.sbom_key}<a class="detail-list__value" href={metadataHref(latest, 'sbom.json')}>Open SBOM</a>{:else}<span class="detail-list__value">Pending</span>{/if}</div>
                <div class="detail-list__row"><span class="detail-list__key">Attestation</span>{#if latest.provenance_key}<a class="detail-list__value" href={metadataHref(latest, 'provenance.json')}>Open provenance</a>{:else}<span class="detail-list__value">Pending</span>{/if}</div>
              </div>
            {:else}
              <p class="prose">Evidence links appear once a build is reviewed and published.</p>
            {/if}
          </section>

          <section class="workbench-panel" aria-labelledby="source-title">
            <div class="workbench-panel__head"><h2 id="source-title">Source record</h2><Icon name="git" size={18} /></div>
            {#if request}
              <div class="detail-list">
                <div class="detail-list__row"><span class="detail-list__key">Request</span><span class="detail-list__value hash">{request.id}</span></div>
                <div class="detail-list__row"><span class="detail-list__key">Input type</span><span class="detail-list__value">{sourceKindLabel(request.source_kind)}</span></div>
                <div class="detail-list__row"><span class="detail-list__key">Area</span><span class="detail-list__value">{request.area}</span></div>
                {#if revision}
                  <div class="detail-list__row"><span class="detail-list__key">Commit</span><span class="detail-list__value hash">{revision.upstream_commit || 'Resolved during verification'}</span></div>
                  <div class="detail-list__row"><span class="detail-list__key">License</span><span class="detail-list__value">{revision.license || 'Not recorded'}</span></div>
                  <div class="detail-list__row"><span class="detail-list__key">Dependencies</span><span class="detail-list__value">{parseList(revision.dependencies_json).length || 'None recorded'}</span></div>
                {/if}
              </div>
            {:else}
              <p class="prose">Source details are not public for this record.</p>
            {/if}
          </section>

          {#if role !== 'public' || publicCrashReports.length}
            <section class="workbench-panel" aria-labelledby="crash-reports-title">
              <div class="workbench-panel__head"><h2 id="crash-reports-title">{role === 'public' ? 'Release incidents' : 'Scoped crash reports'}</h2><span class="timestamp">{role === 'public' ? 'confirmed' : 'maintainer view'}</span></div>
              {#if crashReports.length}
                <div class="timeline">
                  {#each role === 'public' ? publicCrashReports : crashReports as report}
                    <article class="timeline__item">
                      <strong>{role === 'public' ? 'Confirmed incident' : report.release_id ? `Release ${report.release_id}` : 'Release report'}</strong>
                      <span class="timestamp">{formatDateTime(report.created_at)}{#if role !== 'public' && report.id} · {report.id}{/if}</span>
                      {#if role === 'public'}<p>A maintainer confirmed an incident for this release.</p>{:else}<p>{report.summary}</p>{/if}
                      {#if report.confirmed_at || (report.id && confirmedReports.has(report.id))}
                        <span class="tag tag--positive"><Icon name="check" size={13} />reviewed{#if report.confirmed_at || (report.id && confirmedAt[report.id || ''])} {formatDateTime(report.confirmed_at || confirmedAt[report.id || ''])}{/if}{#if report.confirmed_by || (report.id && confirmedBy[report.id || ''])} · {reportActorLabel(report, 'confirmed')}{/if}</span>
                      {/if}
                      {#if report.resolved_at || (report.id && resolvedReports.has(report.id))}
                        <span class="tag tag--positive"><Icon name="check" size={13} />resolved{#if report.resolved_at || (report.id && resolvedAt[report.id || ''])} {formatDateTime(report.resolved_at || resolvedAt[report.id || ''])}{/if}{#if report.resolved_by || (report.id && resolvedBy[report.id || ''])} · {reportActorLabel(report, 'resolved')}{/if}</span>
                      {/if}
                      {#if report.id && role === 'admin' && !report.resolved_at && !resolvedReports.has(report.id)}
                        <form class="release-actions" on:submit|preventDefault={() => triageCrash(report, triageActions[report.id || ''] || 'resolve')}>
                          <label class="sr-only" for={`resolution-${report.id}`}>Review reason</label>
                          <input id={`resolution-${report.id}`} value={resolutionReasons[report.id] || ''} on:input={(event) => setResolutionReason(report.id || '', (event.currentTarget as HTMLInputElement).value)} required maxlength="2000" placeholder="Review reason" />
                          <button class="button" type="submit" on:click={() => setTriageAction(report.id || '', 'confirm')} disabled={resolvingReport !== '' || !resolutionReasons[report.id]?.trim()}>{resolvingReport === report.id && triageActions[report.id] === 'confirm' ? 'Saving…' : 'Confirm (reviewed)'}<Icon name="check" size={14} /></button>
                          <button class="button" type="submit" on:click={() => setTriageAction(report.id || '', 'resolve')} disabled={resolvingReport !== '' || !resolutionReasons[report.id]?.trim()}>{resolvingReport === report.id && triageActions[report.id] === 'resolve' ? 'Saving…' : 'Resolve'}<Icon name="check" size={14} /></button>
                        </form>
                      {:else if report.id && !report.resolved_at && !resolvedReports.has(report.id) && role !== 'admin'}
                        <span class="timestamp">Administrator access is required to update this report.</span>
                      {:else if role !== 'public' && !report.id}
                        <span class="timestamp">Report actions are unavailable for this record.</span>
                      {/if}
                    </article>
                  {/each}
                </div>
              {:else}
                <EmptyState title="No scoped crash reports." description="Opt-in reports for this package will appear here for maintainer review." icon="activity" />
              {/if}
              {#if resolutionError}<div class="form-notice form-notice--danger" role="alert" style="margin-top: var(--space-lg)">{resolutionError}</div>{/if}
              {#if resolutionSuccess}<div class="form-notice" role="status" style="margin-top: var(--space-lg)">{resolutionSuccess}</div>{/if}
            </section>
          {/if}
        </aside>
      </div>
    </section>
  {:else}
    <section class="section site-width--narrow"><EmptyState title="Package not found." description="This package has no public request or release record." actionLabel="Browse packages" actionHref="/packages" icon="search" /></section>
  {/if}

  <footer class="site-footer"><p>omapkg · inspect before install</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/packages">Packages</a><a href="/docs">Docs</a><a href="/privacy">Privacy</a><a href="/request">Request</a></nav></footer>
</main>
