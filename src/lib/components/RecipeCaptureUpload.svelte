<script lang="ts">
  import { goto } from '$app/navigation';
  import type { InputObject } from '$lib/frozen-inputs';
  import type { ImportSource } from '$lib/imports';
  import { postCaptureRequest, uploadCaptureObjects } from '$lib/input-upload';
  export let importId: string;
  export let sources: ImportSource[];
  let files: FileList | undefined;
  let reference: InputObject | null = null;
  let pkgbase = ''; let commit = ''; let sourceId = ''; let reason = ''; let busy = false; let error = ''; let message = ''; let completed = 0; let total = 0;
  async function readCapture(event: Event) {
    files = (event.currentTarget as HTMLInputElement).files ?? undefined;
    reference = null; pkgbase = ''; commit = ''; error = '';
    try {
      const entries = Array.from(files ?? []);
      const header = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'manifest.json');
      const ref = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'reference.json');
      if (!header || !ref || header.size > 512 * 1024 || ref.size > 1024) throw new Error('Choose the recipe capture folder containing manifest.json, reference.json and objects.');
      const parsed = JSON.parse(await header.text()); const root = JSON.parse(await ref.text());
      if (parsed.kind !== 'recipe-capture' || typeof parsed.pkgbase !== 'string' || typeof parsed.commit !== 'string' || !/^[a-f0-9]{64}$/.test(root.sha256)) throw new Error('Invalid recipe capture header.');
      reference = root; pkgbase = parsed.pkgbase; commit = parsed.commit;
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Could not read recipe capture.'; }
  }
  async function upload() {
    if (busy || !reference || !sourceId) return;
    busy = true; error = ''; completed = 0;
    try {
      await uploadCaptureObjects(files, (progress) => { completed = progress.completed; total = progress.total; message = progress.message; });
      message = 'Verifying original Git directory and comparing captured package metadata…';
      const result = await postCaptureRequest<{ sha256: string }>('/api/maintain/recipes/captures', { capture: reference, importId, sourceId, reason });
      if (!/^[a-f0-9]{64}$/.test(result.sha256)) throw new Error('Invalid retained recipe response.');
      await goto(`/maintain/recipes/${result.sha256}`);
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Recipe capture could not be retained.'; }
    finally { busy = false; }
  }
</script>
<form class="review-form" on:submit|preventDefault={upload}>
  <div class="field"><label for="recipe-capture">Original recipe capture</label><input id="recipe-capture" type="file" webkitdirectory multiple bind:files on:change={readCapture} disabled={busy} required /><p class="field__hint">Select a folder from capture-recipe.py. PKGBUILD, metadata, patches, install files and Git proofs are retained without execution.</p></div>
  {#if reference}<p><strong>{pkgbase}</strong> · commit <span class="hash">{commit}</span></p>{/if}
  <div class="field"><label for="recipe-source">Captured binary or recipe inventory</label><select id="recipe-source" bind:value={sourceId} required disabled={busy}><option value="">Choose matching repository and target</option>{#each sources.filter((source) => source.status === 'captured') as source}<option value={source.id}>{source.collection} · {source.target}</option>{/each}</select></div>
  <div class="field"><label for="recipe-capture-reason">Source mapping reason</label><textarea id="recipe-capture-reason" bind:value={reason} required maxlength="2000" disabled={busy} placeholder="Why this upstream commit corresponds to the captured package"></textarea></div>
  <button class="button" type="submit" disabled={busy || !reference || !sourceId}>{busy ? 'Retaining original files…' : 'Retain and compare recipe'}</button>
  {#if busy}<progress max={total || 1} value={completed} aria-label="Recipe bytes retained"></progress>{/if}
  {#if message}<p role="status">{message}</p>{/if}{#if error}<p class="form-notice form-notice--danger" role="alert">{error} Uploaded objects are reused on retry.</p>{/if}
</form>
