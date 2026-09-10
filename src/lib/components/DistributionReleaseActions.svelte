<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import Icon from './Icon.svelte';
  import type { ReleaseView } from '$lib/release-workbench';

  export let candidate: ReleaseView;
  export let releaseTeam = false;
  let reason = '';
  let baseReason = '';
  let baseArea = '';
  let pending = false;
  let message = '';
  let error = '';

  $: needsReleaseApproval = candidate.blockers.some((blocker) => blocker.code === 'release-review');
  $: baseAreas = [...new Set(candidate.blockers.filter((blocker) => blocker.code === 'base-review' && blocker.owner).map((blocker) => blocker.owner as string))];
  $: if (!baseAreas.includes(baseArea)) baseArea = baseAreas[0] ?? '';
  $: signaturePending = candidate.blockers.some((blocker) => blocker.code === 'signature-pending');
  $: reviewsReady = !candidate.blockers.some((blocker) => blocker.code === 'release-review' || blocker.code === 'base-review');
  $: canSign = releaseTeam && Boolean(candidate.candidateId) && candidate.status === 'candidate' && signaturePending && reviewsReady && candidate.blockers.every((blocker) => blocker.code === 'signature-pending');
  $: canActivate = releaseTeam && !candidate.blockers.length && candidate.status === 'testing' && Boolean(candidate.candidateId);

  async function submit(operation: 'approve' | 'base' | 'sign' | 'activate') {
    const approvalReason = operation === 'base' ? baseReason.trim() : reason.trim();
    if (!candidate.candidateId || ((operation === 'approve' || operation === 'base') && !approvalReason)) return;
    pending = true; message = ''; error = '';
    const body = operation === 'approve' || operation === 'base'
      ? { operation: 'approve', approval: { candidateId: candidate.candidateId, kind: operation === 'base' ? 'base' : 'release', area: operation === 'base' ? baseArea : null, reason: approvalReason } }
      : operation === 'sign'
        ? { operation, candidateId: candidate.candidateId }
      : { operation, candidateId: candidate.candidateId, expectedParent: { digest: candidate.parentDigest ?? null, sequence: candidate.parentSequence ?? null } };
    try {
      const response = await fetch('/api/maintain/distribution-releases', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      const result = await response.json().catch(() => ({})) as { error?: string };
      if (!response.ok) throw new Error(result.error || 'Release action failed. Refresh and review current evidence.');
      message = operation === 'approve' ? 'Release-team approval recorded for this exact manifest.' : operation === 'base' ? `Base-owner approval recorded for ${baseArea}.` : operation === 'sign' ? 'Manifest signature recorded for this exact reviewed candidate.' : 'Activation recorded after server gate checks.';
      if (operation === 'approve') reason = '';
      if (operation === 'base') baseReason = '';
      await invalidateAll();
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Release action failed. Refresh and review current evidence.'; }
    finally { pending = false; }
  }
</script>

{#if baseAreas.length}<form class="release-action-form" on:submit|preventDefault={() => submit('base')}><div class="field"><label for={`base-area-${candidate.candidateId}`}>Base-owner area</label><select id={`base-area-${candidate.candidateId}`} bind:value={baseArea}>{#each baseAreas as area}<option value={area}>{area}</option>{/each}</select></div><div class="field"><label for={`base-reason-${candidate.candidateId}`}>Base-owner approval reason</label><input id={`base-reason-${candidate.candidateId}`} bind:value={baseReason} maxlength="2000" required placeholder="Reviewed exact base ownership and target evidence" /></div><button class="button" type="submit" disabled={pending || !baseArea}>{pending ? 'Recording…' : `Approve ${baseArea} base ownership`}<Icon name="shield" size={14} /></button></form>{/if}
{#if !releaseTeam}<p class="field__hint">Release-team membership is required for release approval, signing, and activation.</p>{:else if needsReleaseApproval}<form class="release-action-form" on:submit|preventDefault={() => submit('approve')}><div class="field"><label for={`release-reason-${candidate.candidateId}`}>Release-team approval reason</label><input id={`release-reason-${candidate.candidateId}`} bind:value={reason} maxlength="2000" required placeholder="Reviewed target evidence, changelog, and compatibility" aria-describedby={`release-action-${candidate.candidateId}`} /></div><button class="button button--primary" type="submit" disabled={pending}>{pending ? 'Recording…' : 'Approve exact release manifest'}<Icon name="shield" size={14} /></button></form>{:else if canSign}<form class="release-action-form" on:submit|preventDefault={() => submit('sign')}><p id={`release-action-${candidate.candidateId}`}>Authority reviews are complete. Sign this exact immutable manifest before activation.</p><button class="button button--primary" type="submit" disabled={pending}>{pending ? 'Signing…' : 'Sign reviewed release manifest'}<Icon name="check" size={14} /></button></form>{:else if canActivate}<form class="release-action-form" on:submit|preventDefault={() => submit('activate')}><p id={`release-action-${candidate.candidateId}`}>The reviewed manifest is signed. Activation still rechecks compatible snapshots, base approvals, and the current parent.</p><button class="button button--primary" type="submit" disabled={pending}>{pending ? 'Activating…' : 'Activate release candidate'}<Icon name="upload" size={14} /></button></form>{:else if candidate.status === 'stable'}<p class="field__hint field__hint--success">Active release. Historical evidence remains immutable.</p>{:else}<p class="field__hint">Resolve every listed blocker before activation. The server is authoritative.</p>{/if}
{#if message}<p class="field__hint field__hint--success" role="status">{message}</p>{/if}
{#if error}<p class="field__hint field__hint--danger" role="alert">{error}</p>{/if}

<style>
  .release-action-form { border-top: var(--border-width) solid var(--color-rule-soft); display: grid; gap: var(--space-md); padding-top: var(--space-md); }
  .release-action-form p { color: var(--color-text); font-family: var(--font-body); }
</style>
