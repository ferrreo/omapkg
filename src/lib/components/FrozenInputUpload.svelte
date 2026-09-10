<script lang="ts">
  import { goto } from '$app/navigation';
  import type { FrozenManifest, InputObject } from '$lib/frozen-inputs';
  import { postCaptureRequest, uploadCaptureObjects } from '$lib/input-upload';
  export let candidates: { id: string; pkgbase: string; title: string; cohort_sha256: string; recipe_sha256: string }[];
  let files: FileList | undefined;
  let manifest: FrozenManifest | null = null;
  let reference: InputObject | null = null;
  let revisionId = ''; let reason = ''; let busy = false; let error = ''; let message = ''; let completed = 0; let total = 0;
  $: matches = manifest ? candidates.filter((item) => item.recipe_sha256 === manifest!.recipeSha256 && item.cohort_sha256 === manifest!.cohortSha256) : [];
  async function readCapture(event: Event) {
    files = (event.currentTarget as HTMLInputElement).files ?? undefined;
    manifest = null; reference = null; revisionId = ''; error = '';
    try {
      const entries = Array.from(files ?? []);
      const header = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'manifest.json');
      const ref = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'reference.json');
      if (!header || !ref || header.size > 128 * 1024 || ref.size > 1024) throw new Error('Choose the capture folder containing manifest.json, reference.json and objects.');
      const parsed = JSON.parse(await header.text()); const root = JSON.parse(await ref.text());
      if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.environments) || !/^[a-f0-9]{64}$/.test(root.sha256)) throw new Error('Invalid frozen capture header.');
      manifest = parsed; reference = root;
      revisionId = candidates.find((item) => item.recipe_sha256 === parsed.recipeSha256 && item.cohort_sha256 === parsed.cohortSha256)?.id ?? '';
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Could not read capture.'; }
  }
  async function upload() {
    if (busy || !manifest || !reference || !revisionId) return;
    busy = true; error = ''; completed = 0;
    try {
      await uploadCaptureObjects(files, (progress) => { completed = progress.completed; total = progress.total; message = progress.message; });
      message = 'Checking complete input closure and retained source evidence…';
      const result = await postCaptureRequest<{ sha256: string }>('/api/maintain/inputs/locks', { revisionId, lock: reference, reason });
      if (typeof result.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(result.sha256)) throw new Error('Server returned invalid input lock.');
      await goto(`/maintain/inputs/${result.sha256}`);
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Input capture could not be retained.'; }
    finally { busy = false; }
  }
</script>
<form class="review-form" on:submit|preventDefault={upload}>
  <div class="field"><label for="frozen-capture">Captured input folder</label><input id="frozen-capture" type="file" webkitdirectory multiple bind:files on:change={readCapture} disabled={busy} required /><p class="field__hint">Select the folder created by capture-bootstrap-inputs.py. Package bytes, signatures, keys and helper image upload in resumable chunks.</p></div>
  {#if manifest}<p><strong>{manifest.architecture} · {manifest.purpose}</strong> · {manifest.environments.length} environments</p><div class="field"><label for="input-recipe">Matching recipe and cohort</label><select id="input-recipe" bind:value={revisionId} required disabled={busy}><option value="">Choose matching reviewed scope</option>{#each matches as item}<option value={item.id}>{item.pkgbase} · {item.title}</option>{/each}</select>{#if !matches.length}<p class="field__hint">No current recipe and cohort match this capture. Open its cohort and capture the exact current recipe and cohort checksums.</p>{/if}</div>{/if}
  <div class="field"><label for="input-reason">Why these inputs</label><textarea id="input-reason" bind:value={reason} required maxlength="2000" disabled={busy} placeholder="Source of this seed, key verification and intended private rebuilds"></textarea></div>
  <button class="button button--primary" type="submit" disabled={busy || !revisionId}>{busy ? 'Retaining inputs…' : 'Upload for independent review'}</button>
  {#if busy}<progress max={total || 1} value={completed} aria-label="Input bytes retained"></progress>{/if}
  {#if message}<p role="status">{message}</p>{/if}{#if error}<p class="form-notice form-notice--danger" role="alert">{error} Identical uploaded objects are reused when you retry.</p>{/if}
</form>
