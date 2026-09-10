<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { onDestroy } from 'svelte';
  export let cohortId: string;
  export let revision: number;
  export let manifestSha256: string;
  export let pageCount: number;
  export let phase: string;
  let running = false;
  let stopped = false;
  let completed = 0;
  let message = '';
  let failed = false;
  onDestroy(() => { stopped = true; });
  async function check() {
    if (running) return;
    const target = { cohortId, revision, manifestSha256, phase }; const count = pageCount;
    running = true; stopped = false; failed = false;
    try {
      const parameters = new URLSearchParams({ operation: 'progress', cohortId: target.cohortId, manifestSha256: target.manifestSha256 });
      const response = await fetch(`/api/maintain/cohorts?${parameters}`);
      const progress = await response.json() as { error?: string; epoch: string; nextPage: number | null; firstFailed: number | null };
      if (!response.ok) throw new Error(progress.error ?? 'Cannot read cohort progress.');
      completed = Math.min(progress.nextPage ?? count, progress.firstFailed ?? count);
      for (let page = completed; page < count && !stopped; page++) {
        message = `Verifying member check ${page + 1} of ${count}.`;
        const result = await fetch('/api/maintain/cohorts', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operation: 'check', ...target, page }) });
        const report = await result.json() as { error?: string; epoch: string };
        if (!result.ok) throw new Error(report.error ?? 'Page verification failed.');
        if (report.epoch !== progress.epoch) throw new Error('Build or review evidence changed. Resume to check the current evidence.');
        completed++;
      }
      message = stopped ? 'Checks paused. Resume to check remaining pages.' : 'Page checks recorded. Required blockers still prevent progression.';
    } catch (cause) { failed = true; message = cause instanceof Error ? cause.message : 'Page verification failed.'; }
    finally { running = false; await invalidateAll(); }
  }
</script>
<div class="actions"><button type="button" class="button" on:click={check} disabled={running}>Verify remaining member pages</button>{#if running}<button type="button" class="button" on:click={() => { stopped = true; }}>Pause after current page</button>{/if}</div>
{#if running}<progress value={completed} max={pageCount} aria-label="Cohort member pages checked"></progress>{/if}
{#if message}<p class:form-notice--danger={failed} class="form-notice" role={failed ? 'alert' : 'status'}>{message}</p>{/if}
<style>.actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-block: 1rem; } progress { max-width: 100%; }</style>
