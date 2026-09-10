<script lang="ts">
  import { enhance } from '$app/forms';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import CatalogPolicyForm from '$lib/components/CatalogPolicyForm.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;

  export let form: ActionData;

  let busy = false;

  $: canReview = data.actor.role !== 'maintainer' || data.actor.areas.includes(data.manifest.ownerArea);
</script>
<svelte:head><title>{data.record.pkgbase} · catalog ownership · omapkg</title></svelte:head>
<MaintainerShell active="catalog" user={data.user}>
  <section class="maintainer-page">
    <header class="maintainer-page__head"><div><a href="/maintain/catalog">Catalog ownership</a><h1>{data.record.pkgbase}</h1><p>{data.manifest.description}</p></div><span class="tag">{data.record.admitted_revision === data.record.revision ? 'Admitted policy' : 'Ownership review required'}</span></header>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{:else if form?.success}<p class="notice-bar" role="status">Review recorded. Package build and release approval remain separate.</p>{/if}
    <section class="workbench-panel"><div class="workbench-panel__head"><h2>Revision {data.record.revision}</h2><span class="tag">{data.manifest.lane === 'system' ? 'Versioned system release' : 'Independent OPR package'}</span></div><dl class="detail-list"><div class="detail-list__row"><dt>Repository / role</dt><dd>{data.manifest.collection} / {data.manifest.role}</dd></div><div class="detail-list__row"><dt>Owner</dt><dd>{data.manifest.ownerArea}</dd></div><div class="detail-list__row"><dt>Source</dt><dd><a href={data.manifest.upstreamUrl}>{data.manifest.upstreamUrl}</a></dd></div><div class="detail-list__row"><dt>Build targets</dt><dd>{data.manifest.architectures.join(', ')}</dd></div><div class="detail-list__row"><dt>Package outputs</dt><dd>{data.manifest.outputs.map((name) => `${name} (${data.manifest.portableOutputs?.includes(name) ? 'any' : data.manifest.artifactArchitecture})`).join(', ')}</dd></div></dl>{#each data.manifest.architectureExceptions as exception}<p class="form-notice">{exception.architecture} exception: {exception.reason}</p>{/each}<details><summary>Exact policy evidence</summary><pre class="code-block">{JSON.stringify(data.manifest, null, 2)}</pre><p class="hash">{data.record.manifest_sha256}</p></details></section>
    <section class="workbench-panel"><h2>Ownership sign-offs</h2><p>Record area and security checks for this policy. One account can sign off both when it has the required permissions. This does not approve a recipe or publish a binary.</p>{#each ['area', 'security'] as kind}{@const review = data.reviews.find((item) => item.kind === kind)}<p><strong>{kind === 'area' ? 'Area review' : 'Security review'}:</strong> {review ? review.reason : 'Required'}</p>{/each}
      {#if canReview}<form method="POST" action="?/approve" class="review-form" use:enhance={() => { busy = true; return async ({ update }) => { await update(); busy = false; }; }}><input type="hidden" name="revision" value={data.record.revision} /><input type="hidden" name="digest" value={data.record.manifest_sha256} /><div class="field"><label for="review-kind">Review authority</label><select id="review-kind" name="kind"><option value="area">Area owner</option>{#if data.actor.role === 'security' || data.actor.role === 'admin'}<option value="security">Security reviewer</option>{/if}</select></div><div class="field"><label for="review-reason">Review reason</label><textarea id="review-reason" name="reason" required maxlength="2000" rows="2"></textarea></div><button class="button button--primary" type="submit" disabled={busy}>{busy ? 'Recording review…' : 'Approve this policy revision'}</button></form>{:else}<p>Review requires access to the {data.manifest.ownerArea} area.</p>{/if}
    </section>
    <details class="workbench-panel"><summary>Propose a policy change</summary>{#key data.record.revision}<CatalogPolicyForm value={data.manifest} revision={data.record.revision} />{/key}</details>
    <section class="workbench-panel"><h2>Policy history</h2>{#each data.history as revision}<p><strong>Revision {revision.revision}</strong> · {revision.reason}<br /><span class="hash">{revision.manifest_sha256}</span></p>{/each}</section>
  </section>
</MaintainerShell>
