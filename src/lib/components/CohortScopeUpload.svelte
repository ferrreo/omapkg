<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { onDestroy } from 'svelte';
  import type { CohortScopeInput } from '$lib/server/cohorts';

  export let cohortId: string;

  export let revision: number;

  let files: FileList | undefined;

  let reason = '';

  let running = false;

  let stopped = false;

  let message = '';

  let failed = false;

  let completed = 0;

  let total = 0;

  onDestroy(() => { stopped = true; });

  async function submit() {
    const file = files?.[0];

 if (!file || running) return;
    const target = { cohortId, expectedRevision: revision };
    running = true; stopped = false; failed = false; completed = 0;

    try {
      if (file.size > 32 * 1024 * 1024) throw new Error('Scope file exceeds 32 MiB.');
      const source = await file.text(); const input = JSON.parse(source) as CohortScopeInput;

      if (!input || !Array.isArray(input.members) || !input.members.length || input.members.length > 100000 || input.members.some((member) => !member || typeof member.pkgbase !== 'string')) throw new Error('Choose a scope JSON file containing 1–100,000 package members.');
      const { members, ...metadata } = input;
      members.sort((a, b) => a.pkgbase < b.pkgbase ? -1 : a.pkgbase > b.pkgbase ? 1 : 0); total = members.length;
      const proposalId = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source)))].map((byte) => byte.toString(16).padStart(2, '0')).join('');

      const send = async (value: unknown) => {
        const response = await fetch('/api/maintain/cohorts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
        const result = await response.json() as { error?: string; id: string; member_count: number; next_chunk: number; unchanged?: boolean };

        if (!response.ok) throw Object.assign(new Error(result.error ?? 'Scope upload failed.'), { status: response.status });

        return result;
      };

      const upload = await send({ operation: 'begin', ...target, metadata, memberCount: total, proposalId });
      completed = upload.member_count; let index = upload.next_chunk; let chunkSize = 100;

      while (completed < total && !stopped) {
        message = `Uploading scope: ${completed} of ${total} members. Current cohort remains selected.`;

        try {
          await send({ operation: 'append', uploadId: upload.id, index, members: members.slice(completed, completed + chunkSize) });
        } catch (cause) {
          if (cause && typeof cause === 'object' && 'status' in cause && cause.status === 413 && chunkSize > 1) { chunkSize = Math.max(1, Math.floor(chunkSize / 2)); continue; }

          throw cause;
        }

        completed += Math.min(chunkSize, total - completed); index++;
      }

      if (stopped) { message = 'Scope upload paused. Select the same file to resume.';

 return; }

      message = 'Selecting the complete scope revision.';
      const result = await send({ operation: 'seal', uploadId: upload.id, reason });
      message = 'Scope selected. Refreshing phase review.';
      await invalidateAll();
      message = result.unchanged ? 'Scope already matches the current revision.' : 'Complete scope selected. Phase review has restarted.';
    } catch (cause) { failed = true; message = cause instanceof Error ? cause.message : 'Scope upload failed.'; }
    finally { running = false; }
  }
</script>
<form on:submit|preventDefault={submit} class="review-form">
  <div class="field"><label for="cohort-scope-file">Complete scope proposal (JSON)</label><input id="cohort-scope-file" type="file" accept="application/json,.json" bind:files required disabled={running} /><span class="field-help">Include every affected package with its exact catalog and recipe revisions. Maximum 32 MiB.</span></div>
  <div class="field"><label for="cohort-scope-reason">Why does this scope change?</label><textarea id="cohort-scope-reason" bind:value={reason} maxlength="2000" rows="2" required disabled={running}></textarea></div>
  <div class="actions"><button type="submit" class="button button--primary" disabled={running}>Upload and propose complete scope</button>{#if running}<button type="button" class="button" on:click={() => { stopped = true; }}>Pause after current chunk</button>{/if}</div>
  {#if running && total}<progress value={completed} max={total} aria-label="Scope members uploaded"></progress>{/if}
  {#if message}<p class:form-notice--danger={failed} class="form-notice" role={failed ? 'alert' : 'status'}>{message}</p>{/if}
</form>
<style>.actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-block: 1rem; } progress { max-width: 100%; }</style>
