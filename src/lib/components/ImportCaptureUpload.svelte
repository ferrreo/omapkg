<script lang="ts">
  import { goto } from '$app/navigation';
  let files: FileList | undefined;
  let busy = false;
  let message = '';
  let error = '';
  async function post(input: unknown) {
    const response = await fetch('/api/maintain/imports', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
    const data = await response.json() as { error?: string; importId?: string; status?: string; received?: number };
    if (!response.ok) throw new Error(data.error || 'Import upload failed.');
    return data;
  }
  async function upload() {
    if (busy || !files?.[0]) return;
    busy = true; error = ''; message = 'Reading capture file…';
    try {
      if (files[0].size > 64 * 1024 * 1024) throw new Error('Capture file exceeds 64 MiB. Use the pipeline capture flow.');
      const capture = JSON.parse(await files[0].text());
      if (!capture.manifest || !Array.isArray(capture.entries)) throw new Error('Choose capture.json produced by the catalog capture tool.');
      const { importId, status } = await post({ operation: 'begin', manifest: capture.manifest });
      if (!importId || !/^[a-f0-9]{64}$/.test(importId) || !['capturing', 'captured', 'reconciled'].includes(status ?? '')) throw new Error('The server returned an invalid capture identity.');
      if (status === 'capturing') {
        for (let offset = 0; offset < capture.entries.length; offset += 50) {
          const result = await post({ operation: 'append', importId, entries: capture.entries.slice(offset, offset + 50) });
          if (!Number.isSafeInteger(result.received)) throw new Error('The server could not confirm upload progress.');
          message = `Uploaded ${result.received} of ${capture.entries.length} package records.`;
        }
        message = 'Verifying captured index and source counts…';
        await post({ operation: 'seal', importId });
      }
      await goto(`/maintain/imports/${importId}`);
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Capture file could not be uploaded.'; }
    finally { busy = false; }
  }
</script>
<form on:submit|preventDefault={upload} class="review-form">
  <div class="field"><label for="capture-file">Captured repository metadata</label><input id="capture-file" type="file" accept=".json,application/json" bind:files required disabled={busy} /><p class="field__hint">Upload capture.json from the offline capture tool. Uploading records does not admit or publish packages.</p></div>
  <button class="button" type="submit" disabled={busy || !files?.length}>{busy ? 'Uploading capture…' : 'Upload and verify capture'}</button>
  {#if message}<p role="status">{message}</p>{/if}{#if error}<p class="form-notice form-notice--danger" role="alert">{error} Retrying resumes identical uploaded records.</p>{/if}
</form>
