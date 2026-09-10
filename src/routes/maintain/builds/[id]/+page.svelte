<script lang="ts">
  import { enhance } from '$app/forms';
  import { onMount } from 'svelte';
  import { invalidateAll } from '$app/navigation';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import { startVisibleRefresh } from '$lib/visible-refresh';
  import type { Build, Revision } from '$lib/model';
  import type { PageData, ActionData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  type DependencyPackage = { releaseId: string; name: string; version: string; architecture: string; filename: string; url: string; sha256: string; size: number; signatureUrl: string; signatureSha256: string };
  type DependencyPlan = { channel: 'stable' | 'dev'; publicKeyUrl: string; publicKeyFingerprint: string; packages: DependencyPackage[] };
  type BuildWithDependencyPlan = Build & { dependency_plan_json?: string | null };
  $: build = data?.build as BuildWithDependencyPlan | null;
  $: revision = data?.revision as Revision | null;
  $: logs = Array.isArray(data?.logs) ? data.logs : [];
  $: user = data?.user || null;
  $: logText = logs.map((entry: { text: string }) => entry.text).join('\n');
  $: dependencyPlan = parseDependencyPlan(build?.dependency_plan_json);

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  function pretty(value: string | null | undefined) {
    if (!value) return '—';
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }

  function parseDependencyPlan(value: string | null | undefined): DependencyPlan | null {
    if (!value) return null;
    try {
      const parsed = JSON.parse(value) as Record<string, unknown>;
      if ((parsed.channel !== 'stable' && parsed.channel !== 'dev') || typeof parsed.publicKeyUrl !== 'string' || typeof parsed.publicKeyFingerprint !== 'string' || !Array.isArray(parsed.packages)) return null;
      const packages = parsed.packages.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object' && !Array.isArray(item));
      if (packages.length !== parsed.packages.length) return null;
      if (!packages.every((item) => ['releaseId', 'name', 'version', 'architecture', 'filename', 'url', 'sha256', 'signatureUrl', 'signatureSha256'].every((key) => typeof item[key] === 'string') && typeof item.size === 'number' && Number.isFinite(item.size) && item.size >= 0)) return null;
      return {
        channel: parsed.channel,
        publicKeyUrl: parsed.publicKeyUrl,
        publicKeyFingerprint: parsed.publicKeyFingerprint,
        packages: packages as unknown as DependencyPackage[]
      };
    } catch {
      return null;
    }
  }

  function formatBytes(value: number) {
    return `${value.toLocaleString()} bytes`;
  }

  onMount(() => startVisibleRefresh(
    () => ['queued', 'leased'].includes(build?.status || ''),
    () => { void invalidateAll(); }
  ));
</script>

<svelte:head><title>Build {build?.id || ''} · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="queue" {user}>
  <section class="maintainer-page" aria-labelledby="build-title">
    {#if build}
      <header class="maintainer-page__head"><div><span class="eyebrow">Build {build.id}</span><h1 id="build-title">{build.architecture} build</h1><p>{revision ? `Revision ${revision.id}` : 'Revision details are unavailable.'}</p></div><div class="release-actions"><StatusPill status={build.status} />{#if revision}<a class="button" href={`/maintain/requests/${encodeURIComponent(revision.request_id)}`}>Open request<Icon name="arrow" size={14} /></a>{/if}</div></header>

      {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{:else if form?.success}<p class="notice-bar" role="status">Action recorded. Signed output remains private until its release is approved.</p>{/if}
      {#if data.outputContract && build.error}<p class="form-notice form-notice--danger" role="status">{build.error}</p>{/if}
      <div class="detail-grid">
        <div class="detail-stack">
          {#if data.outputContract}
            <section class="workbench-panel" aria-labelledby="outputs-title"><div class="workbench-panel__head"><h2 id="outputs-title">Package outputs</h2><a href={`/maintain/cohorts/${encodeURIComponent(data.outputContract.cohort.id)}`}>Cohort revision {data.outputContract.cohort.revision}</a></div><p>Every expected output must pass native validation before this build can complete.</p><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Content</th><th>Artifact</th><th>Signature</th></tr></thead><tbody>{#each data.outputs as output}<tr><td>{output.name}</td><td>{output.fullVersion}</td><td>{output.architecture}</td><td>{#if output.artifact}<a href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact?filename=${encodeURIComponent(output.filename)}`} download={output.filename}>{output.filename}</a><div class="hash">{output.artifact.sha256}</div><span class="timestamp">{formatBytes(output.artifact.size)} · uploaded</span>{:else}<span class="timestamp">Awaiting output</span>{/if}</td><td>{#if output.signature}<a href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact?filename=${encodeURIComponent(output.filename)}&signature=1`}>Download signature</a><div class="timestamp">Signed · private</div>{:else if data.canSign}<form method="POST" action="?/sign" use:enhance><input type="hidden" name="attempt" value={build.attempt} /><input type="hidden" name="filename" value={output.filename} /><button class="button" type="submit" aria-label={`Sign private output ${output.name}`}>Sign private output</button></form>{:else}<span class="timestamp">Awaiting signing</span>{/if}</td></tr>{/each}</tbody></table></div>
              <p>Native build statement covers every output and installation group. {build.input_lock_sha256 ? 'Build uses a frozen input lock; cohort qualification and release approval remain required.' : 'Current inputs are from shadow operation; signing does not qualify an owned release.'}</p>
              {#if build.input_lock_sha256}<p><a href={`/maintain/inputs/${build.input_lock_sha256}`}>Review frozen inputs</a></p>{/if}
              {#if data.outputs.some((output) => output.abi)}<details><summary>Recorded ABI inventories</summary><p>File and symbol observations bind exact package bytes. C/C++ type compatibility still needs separate qualification.</p><ul>{#each data.outputs as output}{#if output.abi}<li><a href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact?attempt=${build.attempt}&evidence=${output.abi.sha256}`}>Download {output.name} ABI inventory</a></li>{/if}{/each}</ul></details>{/if}
              {#if data.statementSigned}<a class="button" href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact?filename=attestation.json`}>Download statement</a> <a class="button" href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact?filename=attestation.json&signature=1`}>Statement signature</a>{:else if data.canSign}<form method="POST" action="?/sign" use:enhance><input type="hidden" name="attempt" value={build.attempt} /><input type="hidden" name="filename" value="attestation.json" /><button class="button" type="submit">Sign native build statement</button></form>{/if}
              {#if data.canRetain && data.statementSigned}<h3>Retain as private build inputs</h3>{#each data.outputs.filter((output) => output.signature) as output}{#if data.retained.some((item) => item.package_sha256 === output.artifact?.sha256)}<p>{output.name} · retained in <a href="/maintain/inputs">native input registry</a></p>{:else}<form method="POST" action="?/retain" use:enhance><input type="hidden" name="attempt" value={build.attempt} /><input type="hidden" name="filename" value={output.filename} /><button class="button" type="submit">Retain {output.name} for private builds</button></form>{/if}{/each}{/if}
            </section>
          {/if}
          <section class="workbench-panel" aria-labelledby="logs-title"><div class="workbench-panel__head"><h2 id="logs-title">Live worker log</h2><span class="timestamp">{build.status === 'queued' || build.status === 'leased' ? 'refreshing every 5s' : `${logs.length} chunks`}</span></div>{#if logs.length}<pre class="code-block code-block--logs">{logText}</pre>{:else}<EmptyState title="No log chunks yet." description="A worker appends bounded, ordered output while the lease is active." icon="terminal" />{/if}</section>

          <section aria-labelledby="recipe-title"><div class="workbench-panel__head"><h2 id="recipe-title">Reviewed recipe</h2>{#if revision}<CopyButton value={revision.recipe} label="Copy recipe" />{/if}</div>{#if revision}<pre class="code-block">{revision.recipe}</pre>{:else}<EmptyState title="Recipe unavailable." description="This build is not linked to a visible revision." icon="code" />{/if}</section>

          <section aria-labelledby="provenance-title"><div class="workbench-panel__head"><h2 id="provenance-title">Provenance</h2><Icon name="shield" size={18} /></div>{#if build.provenance}<pre class="code-block">{pretty(build.provenance)}</pre>{:else}<EmptyState title="Attestation pending." description="The worker uploads provenance after the offline build completes. Signing remains a separate service step." icon="lock" />{/if}</section>
        </div>

        <aside class="detail-stack">
          {#if data.preserved}
            <section class="workbench-panel" aria-labelledby="source-inputs-title">
              <div class="workbench-panel__head"><h2 id="source-inputs-title">Reviewed source inputs</h2><Icon name="lock" size={18} /></div>
              <p>Workers verify original files and prepared sources without network access.</p>
              <div class="detail-list">
                <div class="detail-list__row"><span class="detail-list__key">Recipe capture</span><a class="detail-list__value hash" aria-label="Review original recipe capture" href={`/maintain/recipes/${data.preserved.capture.sha256}`}>{data.preserved.capture.sha256}</a></div>
                <div class="detail-list__row"><span class="detail-list__key">{build.architecture} sources</span><a class="detail-list__value hash" aria-label={`Download ${build.architecture} source bundle`} href={`/maintain/recipes/${data.preserved.capture.sha256}/source-bundle?bundle=${data.preserved.sourceBundle.sha256}`} download="recipe-sources.json">{data.preserved.sourceBundle.sha256}</a></div>
              </div>
            </section>
          {/if}
          <section class="workbench-panel" aria-labelledby="build-record-title"><div class="workbench-panel__head"><h2 id="build-record-title">Build record</h2><span class="timestamp">attempt {build.attempt}</span></div><div class="detail-list"><div class="detail-list__row"><span class="detail-list__key">Build</span><span class="detail-list__value hash">{build.id}</span></div><div class="detail-list__row"><span class="detail-list__key">Architecture</span><span class="detail-list__value">{build.architecture}</span></div><div class="detail-list__row"><span class="detail-list__key">Worker</span><span class="detail-list__value">{build.worker_id || 'Unassigned'}</span></div><div class="detail-list__row"><span class="detail-list__key">Started</span><span class="detail-list__value">{formatDate(build.started_at)}</span></div><div class="detail-list__row"><span class="detail-list__key">Finished</span><span class="detail-list__value">{formatDate(build.finished_at)}</span></div><div class="detail-list__row"><span class="detail-list__key">Smoke tests</span><span class="detail-list__value">{build.smoke_passed ? 'passed' : build.status === 'succeeded' ? 'not recorded' : 'pending'}</span></div></div></section>

          {#if !data.outputContract}<section class="workbench-panel" aria-labelledby="artifact-title"><div class="workbench-panel__head"><h2 id="artifact-title">Artifact</h2><Icon name="box" size={18} /></div><div class="detail-list"><div class="detail-list__row"><span class="detail-list__key">File</span>{#if build.artifact_key && build.artifact_filename}<a class="detail-list__value" href={`/maintain/builds/${encodeURIComponent(build.id)}/artifact`} download={build.artifact_filename}>{build.artifact_filename}<Icon name="download" size={14} /></a>{:else}<span class="detail-list__value">{build.artifact_filename || 'Pending'}</span>{/if}</div><div class="detail-list__row"><span class="detail-list__key">SHA-256</span><span class="detail-list__value hash">{build.artifact_sha256 || 'Pending'}</span></div><div class="detail-list__row"><span class="detail-list__key">Size</span><span class="detail-list__value">{build.artifact_size ? `${build.artifact_size.toLocaleString()} bytes` : 'Pending'}</span></div><div class="detail-list__row"><span class="detail-list__key">Result</span><span class="detail-list__value">{build.error || 'No error recorded.'}</span></div></div></section>{/if}

          {#if build.status === 'failed'}
            <section class="workbench-panel" aria-labelledby="retry-title"><div class="workbench-panel__head"><h2 id="retry-title">Retry build</h2><Icon name="refresh" size={18} /></div><p class="prose">{data.preserved ? 'Retry these reviewed inputs after fixing the worker. Changed recipes or sources need a new review.' : 'Queue this same reviewed revision again after fixing the worker or source issue.'}</p><form class="form-actions" method="POST" action="?/retry"><div class="field field--full"><label for="retry-reason">Retry reason</label><input id="retry-reason" name="reason" required maxlength="2000" placeholder="Worker issue fixed" /></div><button class="button button--primary" type="submit"><Icon name="refresh" size={14} />Retry build</button></form></section>
          {/if}

          {#if dependencyPlan}
            <section class="workbench-panel" aria-labelledby="dependency-plan-title"><div class="workbench-panel__head"><h2 id="dependency-plan-title">Resolved dependencies</h2><span class="timestamp">{dependencyPlan.channel} channel · readonly</span></div><div class="detail-list"><div class="detail-list__row"><span class="detail-list__key">Repository key</span><a class="detail-list__value" href={dependencyPlan.publicKeyUrl} rel="noreferrer">Open public key<Icon name="external" size={14} /></a></div><div class="detail-list__row"><span class="detail-list__key">Key fingerprint</span><span class="detail-list__value hash">{dependencyPlan.publicKeyFingerprint}</span></div></div><div class="data-table-wrap" style="margin-top: var(--space-md)"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Package hash</th><th>Signature</th></tr></thead><tbody>{#each dependencyPlan.packages as dependency}<tr><td><a href={`/packages/${encodeURIComponent(dependency.name)}?channel=${dependencyPlan.channel}`}>{dependency.name}</a><div class="timestamp"><a href={dependency.url} rel="noreferrer">{dependency.filename}</a><br />{dependency.releaseId}</div></td><td>{dependency.version}</td><td>{dependency.architecture}</td><td><span class="hash">{dependency.sha256}</span><div class="timestamp">{formatBytes(dependency.size)}</div></td><td><a href={dependency.signatureUrl} rel="noreferrer">Open signature</a><div class="hash">{dependency.signatureSha256}</div></td></tr>{/each}</tbody></table></div></section>
          {/if}

          {#if build.provenance_signature}<section class="workbench-panel" aria-labelledby="signature-title"><div class="workbench-panel__head"><h2 id="signature-title">Worker signature</h2><Icon name="lock" size={18} /></div><pre class="code-block">{build.provenance_signature}</pre></section>{/if}
        </aside>
      </div>
    {:else}
      <EmptyState title="Build not found." description="This build has no maintainer record in the current workspace." actionLabel="Back to workspace" actionHref="/maintain" icon="search" />
    {/if}
  </section>
</MaintainerShell>
