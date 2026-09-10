<script lang="ts">
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { PageData } from './$types';

  export let data: PageData;
</script>

<svelte:head><title>{data.dossier.identity.targetKind} dossier · omapkg</title></svelte:head>
<MaintainerShell active="queue" user={data.user || null}>
  <section class="maintainer-page" aria-labelledby="dossier-title">
    <header class="maintainer-page__head">
      <div><span class="eyebrow">Immutable {data.dossier.identity.targetKind} dossier</span><h1 id="dossier-title">{data.dossier.identity.targetId}</h1><p>{data.dossier.status}</p></div>
      <div class="release-actions"><a class="button" href={`/api/maintain/dossiers/aggregate/${encodeURIComponent(data.dossier.id)}`} download>JSON</a><a class="button" href={`/api/maintain/dossiers/aggregate/${encodeURIComponent(data.dossier.id)}?format=markdown`} download>Markdown</a></div>
    </header>
    <p>Run: <code>{data.dossier.identity.runId}</code></p>
    {#if !data.dossier.evidence.complete}<p class="notice-bar">Evidence is incomplete. Failed and missing members remain listed below.</p>{/if}
    {#each data.dossier.constituents as member}
      <section class="workbench-panel" aria-label={member.key}>
        <h2>{member.pkgbase ?? member.key}</h2><p>{member.status} · {member.architectures.join(', ') || 'Target coverage missing'}</p>
        {#if member.dossierId}<p><a href={`/maintain/dossiers/${encodeURIComponent(member.dossierId)}`}>Package dossier</a></p>{:else if member.revisionId}<p>No package dossier for revision <code>{member.revisionId}</code>.</p>{/if}
        {#if member.error}<p>{member.error}</p>{/if}
        <ul>{#each member.outputs as output}<li>{output.filename} · {output.architecture} · <code>{output.sha256}</code></li>{:else}<li>No retained output.</li>{/each}</ul>
      </section>
    {/each}
    {#if data.dossier.image}<details class="workbench-panel"><summary>Image definition and execution evidence</summary><pre>{JSON.stringify(data.dossier.image, null, 2)}</pre></details>{/if}
  </section>
</MaintainerShell>

<style>
  code, pre { overflow-wrap: anywhere; }
  pre { white-space: pre-wrap; max-width: 100%; overflow: auto; }
</style>
