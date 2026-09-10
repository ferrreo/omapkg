<script lang="ts">
  import type { FactoryDossier } from '$lib/server/factory-dossier';

  export let dossier: FactoryDossier;

  export let markdownUrl = '';

  export let jsonUrl = '';
  export let runUrl = '';

  function bytes(value: number | null) { return value === null ? '—' : `${value.toLocaleString()} bytes`; }
</script>

<section class="workbench-panel" aria-labelledby="dossier-title">
  <div class="workbench-panel__head">
    <div><span class="eyebrow">Immutable package dossier</span><h1 id="dossier-title">{dossier.request.name}</h1></div>
    <div class="release-actions"><a class="button" href={jsonUrl} download>JSON</a><a class="button" href={markdownUrl} download>Markdown</a></div>
  </div>
  <p>Run {#if runUrl}<a href={runUrl}>{dossier.identity.runId}</a>{:else}<code>{dossier.identity.runId}</code>{/if} · revision <code>{dossier.identity.revisionId}</code> · {dossier.revision.version}</p>
  <p>Evidence snapshot. <a href={`/maintain/requests/${encodeURIComponent(dossier.identity.requestId)}`}>Open current request and review authority</a>.</p>
  <div class="detail-list">
    <div class="detail-list__row"><span class="detail-list__key">Recipe SHA-256</span><span class="detail-list__value hash">{dossier.identity.recipeSha256}</span></div>
    <div class="detail-list__row"><span class="detail-list__key">Manifest SHA-256</span><span class="detail-list__value hash">{dossier.identity.manifestSha256}</span></div>
    <div class="detail-list__row"><span class="detail-list__key">Upstream</span><span class="detail-list__value">{dossier.request.upstreamUrl}</span></div>
    <div class="detail-list__row"><span class="detail-list__key">Publication</span><span class="detail-list__value">{dossier.publication.published ? dossier.publication.releases.map((release) => `${release.channel} (${release.id})`).join(', ') : 'Private'}</span></div>
  </div>
</section>

<section class="workbench-panel" aria-labelledby="inputs-title">
  <div class="workbench-panel__head"><h2 id="inputs-title">Recipe and inputs</h2></div>
  <p>{dossier.authoring.buildSystem || 'Build system unavailable'} · {dossier.authoring.template || 'Custom recipe'} · template version {dossier.authoring.templateVersion ?? 'unavailable'}</p>
  <p>{dossier.authoring.rationale || 'Authoring rationale unavailable.'}</p>
  <p>Source commit: <code>{dossier.revision.upstreamCommit || 'unavailable'}</code> · source epoch: {dossier.revision.sourceDateEpoch}</p>
  <p>Supporting files: <code>{dossier.inputs.supportingFilesDigest}</code></p>
  <details><summary>Source and dependency identities</summary><pre>{JSON.stringify({ sources: dossier.revision.sources, sourceDigests: dossier.inputs.sourceDigests, dependencies: dossier.revision.dependencies, makeDependencies: dossier.revision.makeDependencies, dependencyLocks: dossier.inputs.dependencyLocks, builderImages: dossier.inputs.builderImages }, null, 2)}</pre></details>
  <details><summary>Exact recipe</summary><pre>{dossier.revision.recipe}</pre></details>
  <details><summary>Required runtime checks</summary><pre>{JSON.stringify(dossier.revision.smokeCommands, null, 2)}</pre></details>
</section>

<section class="workbench-panel" aria-labelledby="attempts-title">
  <div class="workbench-panel__head"><h2 id="attempts-title">Attempts</h2><span class="timestamp">{dossier.attempts.length} retained</span></div>
  <div class="data-table-wrap"><table class="data-table"><thead><tr><th>Attempt</th><th>Result</th><th>Recipe revisions</th><th>Outputs</th></tr></thead><tbody>
    {#each dossier.attempts as attempt}<tr><td>{attempt.attempt}</td><td>{attempt.result}</td><td>{attempt.revisionIds.join(', ') || '—'}</td><td>{attempt.outputs.length}</td></tr>{:else}<tr><td colspan="4">No build attempts retained.</td></tr>{/each}
  </tbody></table></div>
  {#each dossier.attempts as attempt}
    <details>
      <summary>Attempt {attempt.attempt}: findings and evidence</summary>
      <p>{attempt.trigger || 'No triggering finding retained.'}</p>
      <p>Targets: {attempt.architectures.join(', ') || 'unavailable'} · recipes: {attempt.recipeDigests.join(', ') || 'unavailable'}</p>
      <p>Changed inputs: {attempt.changedInputs.join(', ') || 'None recorded'}</p>
      <ul>{#each attempt.findings as finding}<li>{finding}</li>{:else}<li>No findings recorded.</li>{/each}</ul>
      <p>Workers: {attempt.workerIds.join(', ') || 'unavailable'}</p>
      <pre>{JSON.stringify({ builderImages: attempt.builderImages, runtimeImages: attempt.runtimeImages }, null, 2)}</pre>
      {#each attempt.logs as log}<p><a href={log.url}>Build log</a> · {log.lines} retained lines{log.truncated ? ' · preview truncated' : ''}</p>{#if log.sample}<pre>{log.sample}</pre>{/if}{/each}
    </details>
  {/each}
  {#if !dossier.evidence.attemptEvidenceComplete}<p role="status">Attempt evidence is incomplete. Missing records are not passing checks.</p>{/if}
</section>

<section class="workbench-panel" aria-labelledby="outputs-title">
  <div class="workbench-panel__head"><h2 id="outputs-title">Outputs</h2><span class="timestamp">{dossier.outputs.length} retained</span></div>
  <div class="data-table-wrap"><table class="data-table"><thead><tr><th>File</th><th>Architecture</th><th>Attempt</th><th>SHA-256</th><th>Size</th></tr></thead><tbody>
    {#each dossier.outputs as output}<tr><td><a href={output.evidenceUrl}>{output.filename}</a></td><td>{output.architecture}</td><td>{output.attempt}</td><td class="hash">{output.sha256 || 'missing'}</td><td>{bytes(output.size)}</td></tr>{:else}<tr><td colspan="5">No outputs retained.</td></tr>{/each}
  </tbody></table></div>
</section>

<section class="workbench-panel" aria-labelledby="reviews-title">
  <div class="workbench-panel__head"><h2 id="reviews-title">Reviews and blockers</h2></div>
  <p>Decisions below describe the snapshot; later revocations remain visible on the current request.</p>
  <ul>{#each dossier.reviews as review}<li>{review.kind} · {review.actor} · {review.currentAtSnapshot ? 'Matched this manifest at snapshot' : 'Stale or revoked at snapshot'} · <code>{review.manifestSha256}</code></li>{:else}<li>No reviews recorded.</li>{/each}</ul>
  <ul>{#each dossier.blockers as blocker}<li>{blocker.status}: {blocker.reason}</li>{:else}<li>No stored blockers.</li>{/each}</ul>
  <p><a href={dossier.evidence.auditUrl}>Audit evidence</a></p>
</section>

<section class="workbench-panel" aria-labelledby="rationale-title">
  <div class="workbench-panel__head"><h2 id="rationale-title">Agent explanation and measured usage</h2></div>
  <p>Agent explanations are not check results.</p>
  {#each dossier.rationale as rationale}<p><strong>{rationale.attributedTo}</strong>: {rationale.text}</p>{/each}
  <p>Model: {dossier.modelUsage.model ?? 'unavailable'} · duration: {dossier.modelUsage.durationMs === null ? 'unavailable' : `${dossier.modelUsage.durationMs} ms`}</p>
  <p>Input tokens: {dossier.modelUsage.inputTokens ?? 'unavailable'} · output tokens: {dossier.modelUsage.outputTokens ?? 'unavailable'} · cost: {dossier.modelUsage.cost ?? 'unavailable'}</p>
</section>

<style>
  pre { max-width: 100%; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
  details { margin-block: 1rem; }
  summary { cursor: pointer; }
  code { overflow-wrap: anywhere; }
</style>

<section class="workbench-panel" aria-labelledby="checks-title">
  <div class="workbench-panel__head"><h2 id="checks-title">Checks</h2><span class="timestamp">{dossier.revision.license} · {dossier.revision.surface} · {dossier.revision.architectures.join(', ')}</span></div>
  <ul class="timeline">{#each dossier.checks as check}<li class="timeline__item"><strong>{check.name}</strong><span class="timestamp">{check.status}</span><p>{check.detail}</p></li>{:else}<li class="timeline__item">No check records retained.</li>{/each}</ul>
</section>
