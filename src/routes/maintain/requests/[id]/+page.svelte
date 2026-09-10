<script lang="ts">
  import { onMount } from 'svelte';
  import { invalidateAll } from '$app/navigation';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import { startVisibleRefresh } from '$lib/visible-refresh';
  import type { Approval, AuditEvent, Build, PackageRequest, Revision } from '$lib/model';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;

  export let form: ActionData;

  type LabelledRequest = PackageRequest & Record<string, unknown>;

  type DescribedRevision = Revision & { preserved?: import('$lib/preserved-recipe').PreservedRecipe | null; fullVersion?: string; recipeUrl?: string | null; description?: string | null; recipePolicy?: { mode: string; recorded: boolean }; runtimeExceptions?: Array<{ findingSha256: string; reason: string }> };

  $: request = data?.request as LabelledRequest | null;
  $: revisions = (Array.isArray(data?.revisions) ? data.revisions : []) as DescribedRevision[];
  $: approvals = (Array.isArray(data?.approvals) ? data.approvals : []) as Approval[];
  $: builds = (Array.isArray(data?.builds) ? data.builds : []) as Build[];
  $: events = (Array.isArray(data?.events) ? data.events : []) as AuditEvent[];
  $: actorNames = ((data as unknown as { actorNames?: Record<string, string> })?.actorNames || {}) as Record<string, string>;
  $: factoryEvents = Array.isArray(data?.factoryEvents) ? data.factoryEvents : [];
  $: blockers = data?.blockers ?? [];
  $: selectedRevision = revisions[0] || null;
  $: buildImages = selectedRevision ? imageEntries(selectedRevision.build_images_json) : [];
  $: queueNeedsResume = request?.status === 'queued' && !builds.some((build) => ['queued', 'leased', 'succeeded'].includes(build.status));
  $: user = data?.user || null;
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string } : {};

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  function parseJSON(value: string | null | undefined): unknown {
    if (!value) return null;

    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }

  function pretty(value: string | null | undefined) {
    const parsed = parseJSON(value);

    return parsed === null ? '—' : JSON.stringify(parsed, null, 2);
  }

  function imageEntries(value: string | null | undefined): Array<[string, string]> {
    const parsed = parseJSON(value);

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];

    return Object.entries(parsed).filter((entry): entry is [string, string] => (entry[0] === 'x86_64' || entry[0] === 'aarch64') && typeof entry[1] === 'string');
  }

  function lines(value: string) {
    return value.split('\n').map((line) => ({ text: line || ' ', kind: line.startsWith('+') ? 'add' : line.startsWith('-') ? 'remove' : '' }));
  }

  function sourceKindLabel(value: string | undefined) {
    return value === 'git' ? 'Git repository' : 'Download (source or binary package)';
  }

  function descriptionText(value: unknown, empty: string) {
    return typeof value === 'string' && value.trim() ? value : empty;
  }

  function declaredLicenseLabel(value: unknown) {
    if (value === 'proprietary') return 'Proprietary';

    if (value === 'unknown' || !value) return 'Not sure';

    return String(value);
  }

  function actorLabel(value: string | undefined, record?: Record<string, unknown>) {
    if (value && actorNames[value]) return actorNames[value];

    const display = ['actor_name', 'actor_login', 'github_login', 'github_username', 'display_name', 'username']
      .map((key) => record?.[key]).find((item): item is string => typeof item === 'string' && item.trim().length > 0);

    if (display) return display;

    if (!value) return 'System';

    if (value.startsWith('github:')) return 'GitHub user';

    if (value.startsWith('user:')) return 'Signed-in user';

    return value;
  }

  function requesterLabel(value: string | undefined, requestRecord: LabelledRequest | null) {
    return actorLabel(value, requestRecord || undefined);
  }

  function auditHref(requestId: string | undefined) {
    return requestId ? `/maintain/audit?request=${encodeURIComponent(requestId)}` : '/maintain/audit';
  }

  onMount(() => startVisibleRefresh(
    () => ['queued', 'building', 'blocked'].includes(request?.status || '') || (!data.imported && request?.status === 'generating'),
    () => { void invalidateAll(); }
  ));
</script>

<svelte:head><title>{request?.name || 'Request review'} · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="requests" {user}>
  <section class="maintainer-page" aria-labelledby="review-title">
    {#if request}
      <header class="maintainer-page__head">
        <div><span class="eyebrow">Request {request.id}</span><h1 id="review-title">{request.name}</h1><p>{request.upstream_url}</p></div>
        <div class="release-actions"><StatusPill status={request.status} /><a class="button" href={auditHref(request.id)}>Audit trail<Icon name="log" size={14} /></a></div>
      </header>

      {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success}<div class="notice-bar" role="status"><p>Review action recorded. Current state is shown below.</p><a href={auditHref(request.id)}>Open audit<Icon name="arrow" size={14} /></a></div>{/if}

      {#if revisions.length}
        <section class="workbench-panel" aria-labelledby="dossiers-title">
          <div class="workbench-panel__head"><h2 id="dossiers-title">Package dossiers</h2><span>Immutable evidence snapshots</span></div>
          <form class="review-form" method="POST" action="?/createDossier">
            <label for="dossier-revision">Recipe revision</label>
            <select id="dossier-revision" name="revision_id">{#each revisions as revision}<option value={revision.id}>{revision.fullVersion ?? revision.version} · {revision.id}</option>{/each}</select>
            <button class="button" type="submit">Save dossier snapshot</button>
          </form>
          <ul>{#each data.dossiers as dossier}<li><a href={`/maintain/dossiers/${encodeURIComponent(dossier.id)}`}>{dossier.revision_id} · {formatDate(dossier.created_at)}</a></li>{:else}<li>No snapshots saved. Current evidence remains on this request.</li>{/each}</ul>
        </section>
      {/if}

      {#if data.imported}<p class="notice-bar">Original recipe import. <a href={`/maintain/recipes/${data.imported.capture_sha256}`}>Review captured files, source bundles and upload status</a>.</p>{/if}
      {#if data.imported && ['review', 'queued', 'building', 'failed', 'blocked'].includes(request.status)}
        <details class="workbench-panel"><summary>Reject this import for replacement</summary>
          <p>Rejecting {request.name} cancels queued and running builds. Captured files, reviews and completed evidence remain in history. Review a new import and update cohort scope before building its replacement.</p>
          <form class="review-form" method="POST" action="?/rejectRequest">
            <label for="import-rejection-reason">Reason for rejecting this import</label><input id="import-rejection-reason" name="reason" required maxlength="2000" />
            <button class="button" type="submit">Reject import</button>
          </form>
        </details>
      {/if}
      {#if request.status === 'rejected'}<p class="notice-bar">Rejected: {request.rejection_reason}</p>{/if}
      {#if request.status === 'pending'}
        <div class="notice-bar"><p>Approve this request before factory work begins. Review source scope and area ownership first.</p><div class="release-actions"><form method="POST" action="?/approveRequest"><button class="button button--primary" type="submit">Approve request<Icon name="check" size={14} /></button></form><form method="POST" action="?/rejectRequest"><input name="reason" required placeholder="Reason for rejection" aria-label="Reason for rejection" /><button class="button" type="submit">Reject</button></form></div></div>
      {/if}
      {#if request.status === 'blocked'}
        <section class="workbench-panel" aria-labelledby="dependency-blockers-title">
          <div class="workbench-panel__head"><h2 id="dependency-blockers-title">Dependency blockers</h2><StatusPill status="blocked" /></div>
          <p class="prose">Review the evidence before choosing a dependency source. New requests enter the normal approval queue. Recipe and exception findings require regeneration and another review.</p>
          {#each blockers.filter((blocker) => blocker.status === 'open') as blocker}
            <article class="workbench-panel">
              <h3>{blocker.relation ?? 'Unresolved runtime requirement'} · {blocker.architecture}</h3>
              <p class="prose">{blocker.detail}</p>
              {#each data.dependencyProposals.filter((proposal) => proposal.blocker_id === blocker.id) as proposal}
                <p><a class="button" href={`/maintain/dependencies/${proposal.id}`}>Review shared OPR proposal</a> <span class="timestamp">{proposal.status} · admission does not authorize publication</span></p>
              {/each}
              {#if blocker.finding_sha256}<p class="hash">{blocker.finding_sha256}</p>{/if}
              {#if blocker.dependency_request_id}<p><a href={`/maintain/requests/${encodeURIComponent(blocker.dependency_request_id)}`}>Open linked dependency request</a></p>{/if}
              {#if blocker.resolution === 'dependency'}
                <form class="review-form" method="POST" action="?/linkDependency">
                  <input type="hidden" name="blocker_id" value={blocker.id} />
                  <label for={`dependency-link-${blocker.id}`}>Existing dependency request ID</label>
                  <input id={`dependency-link-${blocker.id}`} name="dependency_request_id" required />
                  <button class="button" type="submit">Link request</button>
                </form>
                <details><summary>Create a dependency request</summary>
                  <form class="review-form" method="POST" action="?/createDependency">
                    <input type="hidden" name="blocker_id" value={blocker.id} />
                    <input type="hidden" name="area" value={request.area} />
                    <label for={`dependency-name-${blocker.id}`}>Package name</label><input id={`dependency-name-${blocker.id}`} name="name" required />
                    <label for={`dependency-url-${blocker.id}`}>Reviewed upstream URL</label><input id={`dependency-url-${blocker.id}`} name="upstream_url" type="url" required />
                    <label for={`dependency-kind-${blocker.id}`}>Source kind</label><select id={`dependency-kind-${blocker.id}`} name="source_kind"><option value="git">Git</option><option value="archive">Archive</option></select>
                    <label for={`dependency-license-${blocker.id}`}>Declared license</label><input id={`dependency-license-${blocker.id}`} name="declared_license" value="unknown" required />
                    <label for={`dependency-description-${blocker.id}`}>Description</label><input id={`dependency-description-${blocker.id}`} name="description" maxlength="500" />
                    <button class="button" type="submit">Create pending request</button>
                  </form>
                </details>
              {/if}
            </article>
          {/each}
          <div class="release-actions">
            <form method="POST" action="?/recheckDependencies"><button class="button" type="submit">Recheck published providers</button></form>
            {#if !data.imported}<form method="POST" action="?/regenerate"><label for="dependency-regenerate">Recipe or exception changes needed</label><input id="dependency-regenerate" name="reason" required maxlength="2000" /><button class="button" type="submit">Regenerate for review</button></form>{/if}
          </div>
        </section>
      {/if}
      {#if request.status === 'failed' && !revisions.length}
        <div class="notice-bar"><p>The factory stopped before producing a revision. Review the failure below, then retry after fixing its cause.</p>{#if !data.imported}<form method="POST" action="?/regenerate"><input name="reason" required maxlength="2000" placeholder="Why retry the factory" aria-label="Factory retry reason" /><button class="button button--primary" type="submit"><Icon name="refresh" size={14} />Retry factory</button></form>{/if}</div>
      {/if}
      {#if queueNeedsResume}
        <div class="notice-bar"><p>No active build job is attached. Approve the current area and security checks again to resume queueing this revision.</p><span class="tag tag--warning"><Icon name="refresh" size={13} />resume queue</span></div>
      {/if}

      <div class="detail-grid">
        <div class="detail-stack">
          <section class="workbench-panel" aria-labelledby="request-record-title"><div class="workbench-panel__head"><h2 id="request-record-title">Request record</h2><span class="timestamp">updated {formatDate(request.updated_at)}</span></div><div class="detail-list"><div class="detail-list__row"><span class="detail-list__key">Request ID</span><span class="detail-list__value hash">{request.id}</span></div><div class="detail-list__row"><span class="detail-list__key">Source</span><a class="detail-list__value" href={request.upstream_url} rel="noreferrer">{request.upstream_url}<Icon name="external" size={14} /></a></div><div class="detail-list__row"><span class="detail-list__key">Input type</span><span class="detail-list__value">{sourceKindLabel(request.source_kind)}</span></div><div class="detail-list__row"><span class="detail-list__key">Requester description</span><span class="detail-list__value">{descriptionText(request.description, 'No description supplied.')}</span></div><div class="detail-list__row"><span class="detail-list__key">Declared license</span><span class="detail-list__value">{declaredLicenseLabel(request.declared_license)}</span></div><div class="detail-list__row"><span class="detail-list__key">Area</span><span class="detail-list__value">{request.area}</span></div><div class="detail-list__row"><span class="detail-list__key">Requested by</span><span class="detail-list__value">{requesterLabel(request.requested_by, request)}</span></div><div class="detail-list__row"><span class="detail-list__key">Created</span><span class="detail-list__value">{formatDate(request.created_at)}</span></div></div></section>

          <section aria-labelledby="revision-title"><div class="workbench-panel__head"><h2 id="revision-title">Recipe revisions</h2><span class="timestamp">{revisions.length} revision{revisions.length === 1 ? '' : 's'}</span></div>{#if revisions.length}{#each revisions as item}<details class="workbench-panel" open={item.id === selectedRevision?.id}><summary><span>{item.fullVersion ?? item.version}</span><span class="timestamp">{formatDate(item.created_at)} · {item.surface}</span></summary><div class="detail-list" style="margin-top: var(--space-md)"><div class="detail-list__row"><span class="detail-list__key">Revision</span><span class="detail-list__value hash">{item.id}</span></div><div class="detail-list__row"><span class="detail-list__key">Recipe hash</span><span class="detail-list__value hash">{item.recipe_sha256}</span></div><div class="detail-list__row"><span class="detail-list__key">Manifest hash</span><span class="detail-list__value hash">{item.manifest_sha256}</span></div><div class="detail-list__row"><span class="detail-list__key">Factory description</span><span class="detail-list__value">{descriptionText(item.description, 'No final description generated.')}</span></div><div class="detail-list__row"><span class="detail-list__key">Verified license</span><span class="detail-list__value">{item.license || 'Not recorded'}</span></div><div class="detail-list__row"><span class="detail-list__key">Explanation</span><span class="detail-list__value">{item.explanation || 'No explanation recorded.'}</span></div>{#if item.recipeUrl}<div class="detail-list__row"><span class="detail-list__key">Recipe files</span><a class="detail-list__value" href={item.recipeUrl} rel="noreferrer">Open reviewed files<Icon name="external" size={14} /></a></div>{/if}<div class="detail-list__row"><span class="detail-list__key">PR</span>{#if item.pr_url}<a class="detail-list__value" href={item.pr_url} rel="noreferrer">Open pull request<Icon name="external" size={14} /></a>{:else}<span class="detail-list__value">Not linked</span>{/if}</div></div><div class="release-actions" style="margin-top: var(--space-md)"><form class="review-form" method="POST" action="?/approveRevision"><input type="hidden" name="revision_id" value={item.id} />{#if item.runtimeExceptions?.length}<pre class="code-block">{JSON.stringify(item.runtimeExceptions, null, 2)}</pre><label class="field__hint"><input type="checkbox" name="runtime_exceptions_acknowledged" required /> I reviewed each exact runtime finding exception and its reason.</label>{/if}<input type="hidden" name="kind" value="area" />{#if item.recipePolicy?.mode !== 'template'}<label class="field__hint"><input type="checkbox" name="custom_shell_acknowledged" required /> I reviewed custom shell in preparation, build, packaging, public recipe, and smoke checks.</label>{/if}<div class="field"><label for={`area-review-reason-${item.id}`}>Area review reason</label><input id={`area-review-reason-${item.id}`} name="reason" required placeholder="Area review reason" /></div><button class="button button--primary" type="submit">{queueNeedsResume ? 'Resume queue · area' : 'Approve area review'}<Icon name="check" size={14} /></button></form><form class="review-form" method="POST" action="?/approveRevision"><input type="hidden" name="revision_id" value={item.id} />{#if item.runtimeExceptions?.length}<pre class="code-block">{JSON.stringify(item.runtimeExceptions, null, 2)}</pre><label class="field__hint"><input type="checkbox" name="runtime_exceptions_acknowledged" required /> I reviewed each exact runtime finding exception and its reason.</label>{/if}<input type="hidden" name="kind" value="security" />{#if item.recipePolicy?.mode !== 'template'}<label class="field__hint"><input type="checkbox" name="custom_shell_acknowledged" required /> I reviewed custom shell in preparation, build, packaging, public recipe, and smoke checks.</label>{/if}<div class="field"><label for={`security-review-reason-${item.id}`}>Security review reason</label><input id={`security-review-reason-${item.id}`} name="reason" required placeholder="Security review reason" /></div><button class="button" type="submit">{queueNeedsResume ? 'Resume queue · security' : 'Approve security'}<Icon name="shield" size={14} /></button></form>{#if !data.imported}<form class="review-form" method="POST" action="?/regenerate"><input type="hidden" name="revision_id" value={item.id} /><div class="field"><label for={`regenerate-reason-${item.id}`}>Regeneration reason</label><input id={`regenerate-reason-${item.id}`} name="reason" required placeholder="Why regenerate" /></div><button class="button" type="submit"><Icon name="refresh" size={14} />Regenerate</button></form>{/if}</div></details>{/each}{:else}<EmptyState title="No recipe revision." description={data.imported ? 'Resume the saved import from its captured recipe page.' : 'Approve the request before factory output can appear here.'} icon="code" />{/if}</section>

          {#if selectedRevision}
            <section aria-labelledby="diff-title"><div class="workbench-panel__head"><h2 id="diff-title">Generated PKGBUILD · {selectedRevision.recipePolicy?.mode ?? 'custom-shell'}</h2><span class="hash">{selectedRevision.recipe_sha256}</span></div><pre class="diff">{#each lines(selectedRevision.recipe) as line}<span class={`diff__line diff__line--${line.kind}`}>{line.text}</span>{/each}</pre></section>
          {/if}

          <section aria-labelledby="manifest-title"><div class="workbench-panel__head"><h2 id="manifest-title">Reviewed manifest</h2><span class="timestamp">sealed inputs</span></div>{#if selectedRevision}<div class="manifest-grid"><div><h3>Sources</h3>{#if selectedRevision.preserved}{#each Object.entries(selectedRevision.preserved.sources) as [target, bundle]}<p><a href={`/maintain/recipes/${selectedRevision.preserved.capture.sha256}/source-bundle?${new URLSearchParams({ bundle: bundle!.sha256 })}`}>{target} retained source bundle</a></p>{/each}{:else}<pre class="code-block">{pretty(selectedRevision.sources_json)}</pre>{/if}</div><div><h3>Dependencies</h3><pre class="code-block">{pretty(selectedRevision.dependencies_json)}</pre></div><div><h3>Smoke checks</h3><pre class="code-block">{pretty(selectedRevision.smoke_commands_json)}</pre></div></div><div style="margin-top: var(--space-xl)"><h3>Builder images</h3>{#if buildImages.length}<div class="detail-list">{#each buildImages as [architecture, image]}<div class="detail-list__row"><span class="detail-list__key">{architecture}</span><span class="detail-list__value hash">{image}</span></div>{/each}</div>{:else}<p class="field__hint">No per-architecture image map is recorded on this revision.</p>{/if}</div>{:else}<EmptyState title="Manifest pending." description="Source, dependency, and builder image inputs appear with the first generated revision." icon="lock" />{/if}</section>
        </div>

        <aside class="detail-stack">
          <section class="workbench-panel" aria-labelledby="approval-title"><div class="workbench-panel__head"><h2 id="approval-title">Review decisions</h2><Icon name="shield" size={18} /></div>{#if approvals.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Kind</th><th>Actor</th><th>Revision</th></tr></thead><tbody>{#each approvals as approval}<tr><td>{approval.kind}</td><td>{actorNames[approval.actor] || actorLabel(approval.actor, approval as unknown as Record<string, unknown>)}</td><td><span class="hash">{approval.revision_id}</span><div class="timestamp">{formatDate(approval.created_at)}</div></td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No review decisions yet." description="Area and security approvals are recorded against a revision hash." icon="lock" />{/if}</section>

          <section class="workbench-panel" aria-labelledby="build-title"><div class="workbench-panel__head"><h2 id="build-title">Build evidence</h2><a href="/maintain/workers">Fleet<Icon name="arrow" size={14} /></a></div>{#if builds.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Arch</th><th>Status</th><th>Attempt</th></tr></thead><tbody>{#each builds as build}<tr><td><a href={`/maintain/builds/${encodeURIComponent(build.id)}`}>{build.architecture}</a></td><td><StatusPill status={build.status} /></td><td>{build.attempt}<div class="timestamp">{build.worker_id || 'unassigned'}</div></td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No worker lease." description="A build starts only after revision approvals and source verification pass." icon="server" />{/if}</section>

          <section class="workbench-panel" aria-labelledby="events-title"><div class="workbench-panel__head"><h2 id="events-title">Event trail</h2><a href={auditHref(request.id)}>Full audit<Icon name="arrow" size={14} /></a></div>{#if events.length || factoryEvents.length}<ol class="timeline">{#each events.slice(0, 12) as event}<li class="timeline__item"><strong>{event.action}</strong><span class="timestamp">{formatDate(event.created_at)} · {actorNames[event.actor] || actorLabel(event.actor, event as unknown as Record<string, unknown>)}</span><p>{event.detail || event.target}</p></li>{/each}{#each factoryEvents.slice(0, 12) as event}<li class="timeline__item"><strong>factory event</strong><span class="timestamp">recorded</span><p>{typeof event === 'string' ? event : JSON.stringify(event)}</p></li>{/each}</ol>{:else}<EmptyState title="No events recorded." description="Request, factory, review, and build transitions appear in the audit trail." icon="log" />{/if}</section>
        </aside>
      </div>
    {:else}
      <EmptyState title="Request not found." description="This request has no maintainer record in the current workspace." actionLabel="Back to requests" actionHref="/maintain/requests" icon="search" />
    {/if}
  </section>
</MaintainerShell>
