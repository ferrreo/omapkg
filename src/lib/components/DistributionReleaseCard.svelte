<script lang="ts">
  import Icon from './Icon.svelte';
  import StatusPill from './StatusPill.svelte';
  import ReleaseArchitectureMatrix from './ReleaseArchitectureMatrix.svelte';
  import { architectureLabel, releaseCompatibility, releaseDate, releaseKindLabel, releaseStatusLabel, releaseVersion, type ReleaseView } from '$lib/release-workbench';

  export let release: ReleaseView;

  export let compact = false;

  $: title = releaseVersion(release);
  $: compatibility = releaseCompatibility(release);
</script>

<article class:distribution-release--compact={compact} class="distribution-release" aria-labelledby={`release-${release.id}`}>
  <header class="distribution-release__head">
    <div>
      <p class="eyebrow">{releaseKindLabel(release.kind)}{release.identity.generation && release.kind === 'opr' ? ` · generation ${release.identity.generation}` : ''}</p>
      <h2 id={`release-${release.id}`}>{title}</h2>
      <p class="distribution-release__summary">{release.summary}</p>
    </div>
    <StatusPill status={release.status} label={releaseStatusLabel(release.status)} />
  </header>

  <dl class="distribution-release__facts">
    {#if release.kind === 'system'}<div><dt>System release</dt><dd class="system-version">{release.identity.version ?? 'Version not recorded'}</dd></div>{/if}
    {#if release.kind === 'opr'}<div><dt>OPR generation</dt><dd>{release.identity.generation ?? 'Generation not recorded'}</dd></div><div><dt>Package versions</dt><dd>{release.packageVersion ?? `${release.packageChunks ?? 0} immutable package chunk${release.packageChunks === 1 ? '' : 's'}`}</dd></div><div><dt>Compatible system</dt><dd>{compatibility}</dd></div>{/if}
    {#if release.kind === 'resolved-transaction'}<div><dt>Resolved system</dt><dd>{release.identity.version ?? 'Version not recorded'}</dd></div><div><dt>OPR generation</dt><dd>{release.identity.generation ?? 'Generation not recorded'}</dd></div>{/if}
    <div><dt>Channel</dt><dd>{release.channel}</dd></div>
    <div><dt>Phase</dt><dd>{release.phase}{release.condition ? ` · ${release.condition}` : ''}</dd></div>
    <div><dt>Immutable sequence</dt><dd class="hash">{release.sequence}</dd></div>
    <div><dt>Recorded</dt><dd>{releaseDate(release.createdAt)}</dd></div>
    {#if release.expiresAt}<div><dt>Expires</dt><dd>{releaseDate(release.expiresAt)}</dd></div>{/if}
  </dl>

  {#if release.blockers.length}
    <section class="distribution-release__blockers" aria-labelledby={`blockers-${release.id}`}>
      <h3 id={`blockers-${release.id}`}><Icon name="lock" size={15} />{release.blockers.length} release blocker{release.blockers.length === 1 ? '' : 's'}</h3>
      <ul>{#each release.blockers as blocker}<li><strong>{blocker.code}{blocker.architecture ? ` · ${architectureLabel(blocker.architecture)}` : ''}</strong><span>{blocker.reason}</span>{#if blocker.owner}<small>Next owner: {blocker.owner}</small>{/if}{#if blocker.href}<a href={blocker.href}>Open evidence</a>{/if}</li>{/each}</ul>
    </section>
  {/if}

  {#if !compact}<ReleaseArchitectureMatrix architectures={release.architectures} repositories={release.repositories} checks={release.checks} matrixId={`release-matrix-${release.id}`} />{:else if release.architectures.length}<p class="distribution-release__targets">Targets: {release.architectures.map(architectureLabel).join(' · ')}</p>{/if}

  <section class="distribution-release__notes" aria-label="Release notes and recovery">
    <div><h3>Changelog</h3>{#if release.changelog.summary}<p>{release.changelog.summary}</p>{:else}<p>Human-readable changelog is not published for this revision.</p>{/if}<p class="timestamp">{release.changelog.approved ? 'Approved for this exact release digest.' : 'Changelog approval is not recorded.'}{#if release.changelog.comparison} Comparison: {release.changelog.comparison}.{/if}</p><div class="distribution-release__links">{#if release.changelog.markdownUrl}<a href={release.changelog.markdownUrl}>CHANGELOG.md</a>{/if}{#if release.changelog.jsonUrl}<a href={release.changelog.jsonUrl}>changelog.json</a>{/if}{#if release.changelog.digest}<span class="hash">{release.changelog.digest}</span>{/if}</div></div>
    <div><h3>Recovery</h3>{#if release.recovery.predecessor}<p>Recoverable predecessor: <span class="hash">{release.recovery.predecessor}</span></p>{:else}<p>No predecessor is recorded for this release.</p>{/if}{#if release.recovery.instructions}<p>{release.recovery.instructions}</p>{/if}{#if release.recovery.manifestUrl}<a href={release.recovery.manifestUrl}>View recovery manifest</a>{/if}</div>
  </section>

  {#if release.history.length}<details class="distribution-release__history"><summary>Immutable history ({release.history.length})</summary><ol>{#each release.history as entry}<li><span>{entry.label}</span><StatusPill status={entry.status} /><span class="timestamp">{releaseDate(entry.timestamp)}</span>{#if entry.digest}<span class="hash">{entry.digest}</span>{/if}</li>{/each}</ol></details>{/if}
  {#if release.href}<a class="button button--quiet distribution-release__open" href={release.href}>Open release record<Icon name="arrow" size={14} /></a>{/if}
</article>

<style>
  .distribution-release { background: var(--color-surface); border-bottom: var(--border-width) solid var(--color-rule-soft); border-top: var(--border-width) solid var(--color-rule-soft); display: grid; gap: var(--space-lg); min-width: 0; padding: var(--space-xl); }
  .distribution-release--compact { gap: var(--space-md); padding: var(--space-lg); }
  .distribution-release__head { align-items: start; display: flex; flex-wrap: wrap; gap: var(--space-lg); justify-content: space-between; min-width: 0; }
  .distribution-release__head > * { min-width: 0; }
  .distribution-release h2 { color: var(--color-text-strong); margin-top: var(--space-xs); }
  .distribution-release__summary { color: var(--color-text); font-family: var(--font-body); margin-top: var(--space-xs); max-width: 66ch; }
  .distribution-release__facts { display: grid; gap: 0 var(--space-xl); grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr)); min-width: 0; }
  .distribution-release__facts div { border-top: var(--border-width) solid var(--color-rule-soft); display: grid; gap: var(--space-2xs); min-width: 0; padding: var(--space-sm) 0; }
  dt { color: var(--color-text-muted); font-size: var(--text-xs); text-transform: uppercase; }
  dd { color: var(--color-text); margin: 0; overflow-wrap: anywhere; }
  .system-version { color: var(--color-accent-strong); font-size: var(--text-md); font-weight: 700; }
  .distribution-release__blockers { border-left: .2rem solid var(--color-danger); display: grid; gap: var(--space-sm); padding-left: var(--space-md); }
  .distribution-release__blockers h3 { align-items: center; color: var(--color-danger); display: flex; gap: var(--space-xs); }
  .distribution-release__blockers ul { display: grid; gap: var(--space-sm); }
  .distribution-release__blockers li { display: grid; gap: var(--space-2xs); min-width: 0; }
  .distribution-release__blockers li > span { color: var(--color-text); font-family: var(--font-body); }
  .distribution-release__blockers small { color: var(--color-text-muted); }
  .distribution-release__targets { color: var(--color-text-muted); font-size: var(--text-sm); }
  .distribution-release__notes { display: grid; gap: var(--space-xl); grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr)); min-width: 0; }
  .distribution-release__notes > div { border-top: var(--border-width) solid var(--color-rule-soft); display: grid; gap: var(--space-xs); min-width: 0; padding-top: var(--space-sm); }
  .distribution-release__notes p { color: var(--color-text); font-family: var(--font-body); }
  .distribution-release__links { align-items: baseline; display: flex; flex-wrap: wrap; gap: var(--space-sm); min-width: 0; }
  .distribution-release__history { border-top: var(--border-width) solid var(--color-rule-soft); padding-top: var(--space-sm); }
  .distribution-release__history ol { display: grid; gap: var(--space-sm); margin-top: var(--space-sm); }
  .distribution-release__history li { align-items: baseline; display: flex; flex-wrap: wrap; gap: var(--space-sm); min-width: 0; }
  .distribution-release__history li > span:first-child { color: var(--color-text); flex: 1 1 12rem; }
  .distribution-release__open { justify-self: start; }
</style>
