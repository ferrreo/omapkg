<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import type { InputObject } from '$lib/frozen-inputs';
  import { postCaptureRequest, uploadCaptureObjects } from '$lib/input-upload';

  export let captureSha256: string;

  let files: FileList | undefined;

  let reference: InputObject | null = null;

  let architecture = '';

 let reason = '';

 let busy = false;

 let error = '';

 let message = '';

 let completed = 0;

 let total = 0;

  async function readCapture(event: Event) {
    files = (event.currentTarget as HTMLInputElement).files ?? undefined;
    reference = null; architecture = ''; error = '';

    try {
      const entries = Array.from(files ?? []);
      const header = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'manifest.json');
      const plan = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'plan.json');
      const ref = entries.find((file) => file.webkitRelativePath.split('/').length === 2 && file.name === 'reference.json');

      if (!header || !plan || !ref || header.size > 2 * 1024 * 1024 || plan.size > 2 * 1024 * 1024 || ref.size > 1024) throw new Error('Choose the prepared source folder containing manifest.json, plan.json, reference.json and objects.');
      const parsed = JSON.parse(await header.text()), scope = JSON.parse(await plan.text()), root = JSON.parse(await ref.text());

      if (parsed.kind !== 'recipe-source-bundle' || scope.kind !== 'recipe-source-plan' || scope.capture?.sha256 !== captureSha256 ||
          !['x86_64', 'aarch64'].includes(scope.architecture) || !/^[a-f0-9]{64}$/.test(root.sha256)) throw new Error('Source bundle must match this captured recipe and native target.');
      reference = root; architecture = scope.architecture;
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Could not read source bundle.'; }
  }

  async function upload() {
    if (busy || !reference) return;
    busy = true; error = ''; completed = 0;

    try {
      await uploadCaptureObjects(files, (progress) => { completed = progress.completed; total = progress.total; message = progress.message; });
      message = 'Checking retained inputs against signed inspection…';
      await postCaptureRequest(`/api/maintain/recipes/${captureSha256}/sources`, { bundle: reference, reason });
      message = 'Sources retained. Recipe review and offline build verification remain required.';
      await invalidateAll();
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Source bundle could not be retained.'; }
    finally { busy = false; }
  }
</script>
<form class="review-form" on:submit|preventDefault={upload}>
  <div class="field"><label for="recipe-sources">Prepared source folder</label><input id="recipe-sources" type="file" webkitdirectory multiple bind:files on:change={readCapture} disabled={busy} required /><p class="field__hint">Select the retained source bundle for this recipe. Original recipe files remain in their capture.</p></div>
  {#if reference}<p>Native target: <strong>{architecture}</strong></p>{/if}
  <div class="field"><label for="source-preparation-reason">Preparation reason</label><textarea id="source-preparation-reason" bind:value={reason} required maxlength="2000" disabled={busy} placeholder="Source versions, resolved Git refs, prepared caches and signing keys"></textarea></div>
  <button class="button" type="submit" disabled={busy || !reference}>{busy ? 'Retaining sources…' : 'Retain prepared sources'}</button>
  {#if busy}<progress max={total || 1} value={completed} aria-label="Source bytes retained"></progress>{/if}
  {#if message}<p role="status">{message}</p>{/if}{#if error}<p class="form-notice form-notice--danger" role="alert">{error} Uploaded objects are reused on retry.</p>{/if}
</form>
