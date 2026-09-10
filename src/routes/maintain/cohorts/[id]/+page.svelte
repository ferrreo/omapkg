<script lang="ts">
  import { enhance } from '$app/forms';
  import type { SubmitFunction } from '@sveltejs/kit';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import CohortScopeUpload from '$lib/components/CohortScopeUpload.svelte';
  import CohortPageChecks from '$lib/components/CohortPageChecks.svelte';
  import { cohortPhaseLabels, cohortPhases } from '$lib/distribution';
  import { cohortCauses } from '$lib/cohorts';
  import type { ActionData, PageData } from './$types';
  export let data: PageData;
  export let form: ActionData;
  let busy = false;
  let addition = '';
  let narrative = '';
  let narrativeCohort = '';
  const tabs = ['overview', 'changes', 'phases', 'tests', 'history'] as const;
  const date = (timestamp: number) => new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  const enhanceAction: SubmitFunction = () => { busy = true; return async ({ update }) => { await update({ reset: false }); busy = false; }; };
  $: editable = data.canEdit && !['publish', 'observe'].includes(data.record.phase);
  $: currentNotes = data.changelogs.find((entry) => entry.facts_sha256 === data.factsSha256);
  $: chosen = data.packages.find((item) => item.pkgbase === addition) ?? data.packages[0];
  $: if (!addition && data.packages[0]) addition = data.packages[0].pkgbase;
  $: if (narrativeCohort !== data.record.id) {
    narrativeCohort = data.record.id;
    narrative = data.changelogs[0] ? JSON.parse(data.changelogs[0].document_json).narrative : '';
  }
</script>
<svelte:head><title>{data.record.title} · cohort · omapkg</title></svelte:head>
<MaintainerShell active="cohorts" user={data.user}>
  <section class="maintainer-page">
    <header class="maintainer-page__head"><div><a href="/maintain/cohorts">Build cohorts</a><h1>{data.record.title}</h1><p>{data.manifest.lane === 'system' ? `System ${data.manifest.systemVersion}` : 'Independent OPR update'} · revision {data.record.current_revision} · {data.memberCount} package{data.memberCount === 1 ? '' : 's'}</p></div><span class="tag">{cohortPhaseLabels[data.record.phase]} · {data.record.condition}</span></header>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{:else if form?.success}<p class="notice-bar" role="status">Action recorded. Current phase, evidence and generated changes are shown below.</p>{/if}
    <section class="workbench-panel" aria-labelledby="next-action"><h2 id="next-action">{data.gate.blockers.length ? `${data.gate.blockers.length} ${data.gate.blockers.length === 1 ? 'check needs' : 'checks need'} attention` : 'Ready for the next phase check'}</h2>
      <p>{data.facts.state === 'planned' ? 'Changes are planned. Successful builds still need verification and release approval.' : data.facts.state === 'built' ? 'Native builds verified. These packages are awaiting coordinated release.' : 'Publication is recorded in the release history.'}</p>
      {#if data.gate.blockers.length}<ul class="blocker-list">{#each data.gate.blockers.slice(0, 8) as blocker}<li><strong>{blocker.pkgbase ?? 'Cohort'}{blocker.architecture ? ` · ${blocker.architecture}` : ''}:</strong> {blocker.reason}{#if blocker.href}{' '}<a href={blocker.href}>Open review</a>{/if}</li>{/each}</ul>{#if data.gate.blockers.length > 8}<p><a href="?tab=tests">Show all {data.gate.blockers.length} required checks</a></p>{/if}{/if}
      <p class="timestamp">Cohort last changed {date(data.record.updated_at)}. Build and review state checked when this page loaded.</p>
      {#if data.progress}<p>{data.progress.checked} of {data.progress.memberCount} members verified against current evidence; {data.progress.failed} checks have blockers. Changed build evidence or review authority requires another check.</p>
        {#if data.canEdit}<CohortPageChecks cohortId={data.record.id} revision={data.record.current_revision} manifestSha256={data.record.manifest_sha256} phase={data.record.phase} pageCount={data.progress.pages} />{/if}
        {#if data.progress.failed}<p>Checks needing attention{data.progress.failed > 100 ? ' (first 100 shown)' : ''}: {#each data.progress.rows as row}<a href={`?tab=tests&page=${Math.floor(row.page * data.progress.pageSize / 25)}`}>{row.pkgbase}</a>{' '}{/each}</p>{/if}
      {/if}
      {#if editable}<form method="POST" action="?/phase" class="review-form" use:enhance={enhanceAction}>
        <input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="sequence" value={data.record.event_sequence} /><input type="hidden" name="digest" value={data.record.manifest_sha256} />
        <div class="field"><label for="phase-reason">Decision or next action</label><input id="phase-reason" name="reason" required maxlength="2000" placeholder="Explain the transition, retry or hold" /></div>
        <div class="actions">{#if data.gate.next}<button class="button button--primary" name="action" value="advance" type="submit" disabled={busy || data.gate.blockers.length > 0}>Verify and enter {cohortPhaseLabels[data.gate.next].toLowerCase()}</button>{/if}<button class="button" name="action" value="recheck" type="submit" disabled={busy}>Record current checks</button>{#if data.record.condition === 'held'}<button class="button" name="action" value="resume" type="submit" disabled={busy}>Resolve hold</button>{:else}<button class="button" name="action" value="hold" type="submit" disabled={busy}>Hold cohort</button>{/if}</div>
      </form>{:else if !data.canEdit}<p>Changes require access to every affected package area.</p>{/if}
    </section>
    <nav class="cohort-tabs" aria-label="Cohort sections">{#each tabs as tab}<a href={`?tab=${tab}`} aria-current={data.tab === tab ? 'page' : undefined}>{tab[0].toUpperCase() + tab.slice(1)}</a>{/each}</nav>
    {#if ['overview','tests'].includes(data.tab)}<form method="GET" class="search-form"><input type="hidden" name="tab" value={data.tab} /><div class="field"><label for="cohort-member-search">Jump to package</label><input type="search" id="cohort-member-search" name="member" value={data.memberSearch} maxlength="64" required /></div><button class="button" type="submit">Find member</button></form>{#if data.memberSearch && !data.memberFound}<p role="status">Package “{data.memberSearch}” is not in this cohort revision.</p>{/if}{/if}
    {#if ['overview','tests'].includes(data.tab) && data.pageCount > 1}<nav class="actions" aria-label="Cohort member pages">
      {#if data.page > 0}<a class="button" href={`?tab=${data.tab}&page=${data.page - 1}`}>Previous members</a>{/if}<span>Member page {data.page + 1} of {data.pageCount}</span>
      {#if data.page + 1 < data.pageCount}<a class="button" href={`?tab=${data.tab}&page=${data.page + 1}`}>Next members</a>{/if}
    </nav>{/if}
    {#if data.tab === 'overview'}
      <section class="workbench-panel"><h2>Why these packages update together</h2><p>Scope includes exact ownership policy and recipe inputs. Adding, removing or rebinding a member creates a new revision and restarts phase review.</p>
        {#each data.members as member}
          <article class="member" id={`member-${member.pkgbase}`}><div class="member-head"><h3><a href={`/maintain/catalog/${encodeURIComponent(member.pkgbase)}`}>{member.pkgbase}</a></h3><span class="tag">{member.policy.collection} · {member.policy.ownerArea}</span></div><p>{member.reason} <span class="timestamp">({member.cause.replaceAll('-', ' ')})</span></p>
            <p>Policy {member.catalogRevision} · {member.policy.architectures.join(', ')} · {member.recipe ? `Planned ${member.recipe.fullVersion}` : 'Recipe not yet selected'}</p>
            {#if member.recipe}<a href={`/maintain/requests/${encodeURIComponent(member.recipe.requestId)}`}>Review bound recipe</a>{/if}
            {#each member.policy.architectureExceptions as exception}<p class="form-notice">{exception.architecture} is not required: {exception.reason}. This exception belongs to the reviewed catalog policy.</p>{/each}
            {#if editable && data.manifest.schemaVersion === 1}<details><summary>Update this member</summary>
              {#each data.updates.filter((item) => item.pkgbase === member.pkgbase && (item.catalog_revision !== member.catalogRevision || item.recipe_revision_id !== (member.recipe?.id ?? null))) as update, index}
                <form method="POST" action="?/scope" class="review-form" use:enhance={enhanceAction}><input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="digest" value={data.record.manifest_sha256} /><input type="hidden" name="pkgbase" value={member.pkgbase} /><input type="hidden" name="action" value="bind" /><input type="hidden" name="catalogRevision" value={update.catalog_revision} /><input type="hidden" name="recipeRevisionId" value={update.recipe_revision_id ?? ''} />
                  <p>Proposed binding: policy {update.catalog_revision}; {update.full_version ? `recipe ${update.full_version}` : 'no unpublished recipe available'}.</p>
                  <div class="field"><label for={`bind-${member.pkgbase}-${index}`}>Why update the reviewed inputs?</label><input id={`bind-${member.pkgbase}-${index}`} name="reason" required maxlength="2000" /></div><button class="button" type="submit" disabled={busy}>Create revision with this binding</button>
                </form>
              {/each}
              {#if data.memberCount > 1}<form method="POST" action="?/scope" class="review-form" use:enhance={enhanceAction}><input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="digest" value={data.record.manifest_sha256} /><input type="hidden" name="pkgbase" value={member.pkgbase} /><input type="hidden" name="action" value="remove" /><div class="field"><label for={`remove-${member.pkgbase}`}>Why is this package no longer affected?</label><input id={`remove-${member.pkgbase}`} name="reason" required maxlength="2000" /></div><button class="button" type="submit" disabled={busy}>Propose removal from cohort</button></form>{/if}
            </details>{/if}
          </article>
        {/each}
      </section>
      {#if editable && data.manifest.schemaVersion === 1}<section class="workbench-panel"><h2>Add an affected package</h2><form method="GET" class="search-form"><input type="hidden" name="tab" value="overview" /><div class="field"><label for="add-search">Search catalog identities</label><input id="add-search" name="search" value={data.search} maxlength="100" /></div><button class="button" type="submit">Search</button></form>
        {#if chosen}<form method="POST" action="?/scope" class="review-form" use:enhance={enhanceAction}><input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="digest" value={data.record.manifest_sha256} /><input type="hidden" name="action" value="add" /><input type="hidden" name="catalogRevision" value={chosen.revision} />
          <div class="field"><label for="add-package">Affected package</label><select id="add-package" name="pkgbase" bind:value={addition}>{#each data.packages as candidate}<option value={candidate.pkgbase} disabled={data.existingMembers.includes(candidate.pkgbase)}>{candidate.pkgbase} · {candidate.collection}</option>{/each}</select></div>
          <div class="field"><label for="add-cause">Cause</label><select id="add-cause" name="cause">{#each cohortCauses as cause}<option value={cause}>{cause.replaceAll('-', ' ')}</option>{/each}</select></div><div class="field"><label for="add-reason">Why does it need to update with this cohort?</label><textarea id="add-reason" name="reason" required maxlength="2000" rows="2"></textarea></div><button class="button" type="submit" disabled={busy || data.existingMembers.includes(addition)}>Propose added member</button>
        </form>{:else if data.search}<p>No matching catalog identity. <a href="/maintain/catalog">Propose ownership</a> before adding a member.</p>{/if}
      </section>{/if}
      {#if editable}<section class="workbench-panel"><h2>Replace complete scope</h2><p>Large transitions stay in one cohort. Upload all members together; incomplete uploads do not change the current revision.</p><p><a class="button" href={`./${encodeURIComponent(data.record.id)}/scope?digest=${data.record.manifest_sha256}`}>Download complete scope proposal</a></p><CohortScopeUpload cohortId={data.record.id} revision={data.record.current_revision} /></section>{/if}
      <details class="workbench-panel"><summary>Exact cohort manifest</summary><pre class="code-block">{JSON.stringify(data.manifest, null, 2)}</pre><p class="hash">{data.record.manifest_sha256}</p></details>
    {:else if data.tab === 'changes'}
      <section class="workbench-panel"><h2>Generated changes · {data.facts.state}</h2><p>Compared with {data.facts.baseline.kind === 'previous-cohort-revision' ? `cohort revision ${data.facts.baseline.revision}` : 'the initial plan; no earlier cohort revision exists'}. {data.manifest.parentSnapshot ? 'Parent release snapshot is pinned in the manifest.' : 'Parent release snapshot has not been selected.'}</p>
        {#each data.changes as change}<article class="member"><h3>{change.pkgbase} · {change.kind}</h3><p>{change.oldVersion ?? 'No bound recipe'} → {change.newVersion ?? 'No bound recipe'} · {change.newRepository ?? change.oldRepository}</p><p>{change.reason}</p>{#if change.oldVersion === change.newVersion && change.oldRecipeSha256 !== change.newRecipeSha256}<p>Recipe inputs changed without changing this displayed package version.</p>{/if}</article>{/each}
        <p>These facts come from immutable revisions and phase events. Narrative edits cannot alter package or test evidence.</p>
        {#if data.nextChange}<a href={`?tab=changes&changeAfter=${encodeURIComponent(data.nextChange)}`}>Next package changes</a>{/if}
        {#if data.facts.schemaVersion === 2}<p>Complete diff: {data.facts.changes.count} packages. Changelog approval binds the exact current and previous scope manifests and the versioned diff algorithm.</p>{/if}
      </section>
      <section class="workbench-panel"><h2>Human-reviewed narrative</h2>{#if currentNotes}<p>{currentNotes.review_count ? 'Human review recorded for this exact narrative and current facts.' : 'Current narrative needs human review.'}</p><pre class="narrative">{JSON.parse(currentNotes.document_json).narrative}</pre><div class="actions"><a class="button" href={`./${encodeURIComponent(data.record.id)}/changelog?digest=${currentNotes.digest}&format=markdown`}>Download CHANGELOG.md</a><a class="button" href={`./${encodeURIComponent(data.record.id)}/changelog?digest=${currentNotes.digest}&format=json`}>Download changelog.json</a><a class="button" href={`./${encodeURIComponent(data.record.id)}/changelog?digest=${currentNotes.digest}&format=changes`}>Download complete package changes</a></div>{:else}<p>{data.changelogs.length ? 'Previous narrative is stale because cohort facts changed.' : 'No narrative prepared yet.'} Generate current changes and write the user-facing explanation before release review.</p>{/if}
        {#if editable}<form method="POST" action="?/changelog" class="review-form" use:enhance={enhanceAction}><input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="factsDigest" value={data.factsSha256} /><div class="field"><label for="narrative">Changes, migration steps, reboot needs and known issues</label><textarea id="narrative" name="narrative" rows="8" maxlength="16000" required bind:value={narrative}></textarea><span class="field-help">Use verified facts. Do not infer upstream release notes from a version number.</span></div><button class="button" type="submit" disabled={busy}>Save generated changelog and narrative</button></form>
          {#if currentNotes}<form method="POST" action="?/approveChangelog" class="review-form" use:enhance={enhanceAction}><input type="hidden" name="revision" value={data.record.current_revision} /><input type="hidden" name="digest" value={currentNotes.digest} /><div class="field"><label for="changelog-review">Review reason</label><input id="changelog-review" name="reason" required maxlength="2000" /></div><button class="button button--primary" type="submit" disabled={busy}>Approve this exact changelog</button><p>Changelog review grants no package or release authorization.</p></form>{/if}
        {/if}
      </section>
    {:else if data.tab === 'phases'}
      <section class="workbench-panel"><h2>Phase progress</h2><ol class="phase-list">{#each cohortPhases as phase}<li aria-current={phase === data.record.phase ? 'step' : undefined}><strong>{cohortPhaseLabels[phase]}</strong> · {phase === data.record.phase ? `current · ${data.record.condition}` : cohortPhases.indexOf(phase) < cohortPhases.indexOf(data.record.phase) ? 'transition recorded' : 'ahead'}</li>{/each}</ol></section>
      <section class="workbench-panel"><h2>Attributed phase history</h2>{#each data.events as event}<article class="member"><h3>{cohortPhaseLabels[event.phase]} · {event.condition}</h3><p>{event.cause}</p><p class="timestamp">Revision {event.revision} · {date(event.timestamp)} · {event.actor}</p><details><summary>Immutable event evidence</summary><pre class="code-block">{JSON.stringify(event, null, 2)}</pre></details></article>{/each}{#if data.events.length === 100}<a href={`?tab=phases&after=${data.events.at(-1)!.sequence}`}>Next history page</a>{/if}</section>
    {:else if data.tab === 'tests'}
      <section class="workbench-panel"><h2>Native target matrix</h2><p>Required failures and missing targets block progression. A reviewed hardware exception stays visible beside its target.</p>{#each data.pageGate.matrix as row}<article class="matrix-row" id={`member-${row.pkgbase}-${row.architecture}`}><strong>{row.pkgbase}</strong><span>{row.architecture}</span><span>{row.required ? row.status : 'Not required'}</span>{#if row.buildId}<a href={`/maintain/builds/${encodeURIComponent(row.buildId)}`}>Build evidence</a>{/if}{#if row.reason}<p>{row.reason}</p>{/if}</article>{/each}</section>
      <section class="workbench-panel"><h2>Required checks for this member page</h2>{#if data.pageCheckedAt}<p class="timestamp">Verified {date(data.pageCheckedAt)}.</p>{:else}<p>Displayed checks are provisional. Verify this page before advancing.</p>{/if}{#if data.pageGate.blockers.length}<ul class="blocker-list">{#each data.pageGate.blockers as blocker}<li><strong>{blocker.pkgbase ?? 'Cohort'}{blocker.architecture ? ` · ${blocker.architecture}` : ''}:</strong> {blocker.reason}{#if blocker.href} <a href={blocker.href}>Open evidence</a>{/if}</li>{/each}</ul>{:else}<p>Checks for the next phase are ready. Later native, compatibility and release gates still apply.</p>{/if}</section>
    {:else}
      <section class="workbench-panel"><h2>Immutable scope revisions</h2>{#each data.history as revision}<article class="member"><h3>Revision {revision.revision} · {revision.title}</h3><p class="timestamp">{date(revision.created_at)}</p><p class="hash">{revision.manifest_sha256}</p></article>{/each}</section>
      <section class="workbench-panel"><h2>Saved changelogs</h2>{#each data.changelogs as entry}<article class="member"><p>{entry.facts_sha256 === data.factsSha256 ? 'Current facts' : 'Earlier facts'} · {entry.review_count} human reviews · {date(entry.created_at)}</p><p class="hash">{entry.digest}</p></article>{:else}<p>No saved changelogs yet.</p>{/each}</section>
    {/if}
  </section>
</MaintainerShell>
<style>
  .cohort-tabs { display: flex; flex-wrap: wrap; gap: .6rem; padding-block: .5rem; }
  .cohort-tabs a { padding: .7rem 1rem; border: 1px solid var(--color-rule); border-radius: .4rem; }
  .cohort-tabs a[aria-current="page"] { font-weight: 700; text-decoration: underline; }
  .member { padding-block: 1rem; border-bottom: 1px solid var(--color-rule); }
  .member h3 { margin-block: .4rem; }
  .member-head, .actions, .search-form { display: flex; flex-wrap: wrap; gap: .8rem; align-items: center; }
  .search-form { align-items: end; }
  .search-form .field { flex: 1 1 200px; }
  .actions { margin-block: .8rem; }
  .blocker-list, .phase-list { padding-left: 1.25rem; }
  .blocker-list li, .phase-list li { margin-block: .65rem; }
  .matrix-row { display: flex; flex-wrap: wrap; gap: 1rem; padding-block: 1rem; border-bottom: 1px solid var(--color-rule); }
  .matrix-row strong { flex: 1 1 180px; }
  .matrix-row p { flex-basis: 100%; margin: 0; }
  .narrative { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; }
  .hash { overflow-wrap: anywhere; }
</style>
