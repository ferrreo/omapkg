<script lang="ts">
  import { enhance } from '$app/forms';
  import type { Architecture } from '$lib/model';

  export let targets: Architecture[];

  export let blocked: string | null;

  export let canImport: boolean;

  export let bundles: Array<{ sha256: string; architecture: string; created_at: number; current: number }>;

  export let imports: Array<{ id: string; request_id: string; status: string; reason: string; pr_url: string | null; current: number }>;

  let busy = false;

  const pending = () => { busy = true;

 return async ({ update }: { update: () => Promise<void> }) => { await update(); busy = false; }; };

  $: missingTargets = targets.filter((target) => !bundles.some((bundle) => bundle.current && bundle.architecture === target));
  $: active = imports.some((item) => !['built', 'failed', 'rejected'].includes(item.status));
  $: previous = imports.filter((item) => ['built', 'rejected'].includes(item.status));
</script>

<section class="workbench-panel">
  <h2>Import original recipe for review</h2>
  <p>Create a pull request with every captured file and its original mode. Review metadata lives in a separate directory. Native builds require an approved cohort, retained dependency inputs and a worker that supports preserved recipes.</p>
  {#each imports.filter((item) => !['built', 'rejected'].includes(item.status)) as item}
    <div class="import-record">
      <p><a href={`/maintain/requests/${item.request_id}`}>Open recipe review</a> · {item.status === 'generating' ? 'Upload unfinished' : item.status}</p>
      <p>{item.reason}</p>
      {#if item.pr_url}<p><a href={item.pr_url} rel="noreferrer">Review pull request</a></p>{/if}
      {#if !item.current}<p class="notice-bar">Source or catalog authority changed. Check admission and inspection evidence before continuing.</p>{/if}
      {#if canImport && item.status === 'generating'}
        {#if item.current}<form method="POST" action="?/resumeImport" use:enhance={pending}>
          <input type="hidden" name="importId" value={item.id} />
          <button class="button" type="submit" disabled={busy}>Resume saved import</button>
        </form>{/if}
        <details><summary>Cancel unfinished import</summary>
          <form method="POST" action="?/cancelImport" class="review-form" use:enhance={pending}>
            <input type="hidden" name="importId" value={item.id} />
            <div class="field"><label for={`cancel-import-${item.id}`}>Cancellation reason</label><input id={`cancel-import-${item.id}`} name="reason" required maxlength="2000" /></div>
            <button class="button" type="submit" disabled={busy}>Cancel import</button>
          </form>
        </details>
      {/if}
    </div>
  {/each}
  {#if previous.length}<details><summary>Previous imports ({previous.length})</summary>
    {#each previous as item}<div class="import-record"><p><a href={`/maintain/requests/${item.request_id}`}>Open recipe review</a> · {item.status}</p><p>{item.reason}</p>{#if item.pr_url}<p><a href={item.pr_url} rel="noreferrer">Review pull request</a></p>{/if}</div>{/each}
  </details>{/if}
  {#if blocked}<p class="notice-bar">{blocked}</p>
  {:else if missingTargets.length}<p class="notice-bar">Prepare and retain sources for {missingTargets.join(', ')} before importing this recipe.</p>
  {:else if canImport && !active}
    <form method="POST" action="?/importRecipe" class="review-form" use:enhance={pending}>
      {#each targets as target}
        <div class="field"><label for={`import-bundle-${target}`}>{target} source bundle</label>
          <select id={`import-bundle-${target}`} name="bundle" required>
            <option value="">Choose retained source bundle</option>
            {#each bundles.filter((bundle) => bundle.current && bundle.architecture === target) as bundle}
              <option value={bundle.sha256}>{new Date(bundle.created_at * 1000).toISOString().slice(0, 16)} · {bundle.sha256.slice(0, 16)}</option>
            {/each}
          </select>
        </div>
      {/each}
      <div class="field"><label for="import-smoke">Installed package smoke checks</label><textarea id="import-smoke" name="smokeCommands" required rows="4" maxlength="262144" placeholder="One shell command per line, using installed paths" aria-describedby="import-smoke-hint"></textarea><p id="import-smoke-hint" class="field__hint">Provide checks for the package's expected behavior. Each command must succeed inside its isolated runtime environment.</p></div>
      <div class="field"><label for="import-reason">Import reason and review notes</label><textarea id="import-reason" name="reason" required maxlength="2000" rows="3"></textarea></div>
      <button class="button" type="submit" disabled={busy}>{busy ? 'Preparing review…' : 'Create recipe review'}</button>
    </form>
  {/if}
</section>

<style>
  .import-record { border-bottom: 1px solid var(--border); padding-bottom: var(--space-md); margin-bottom: var(--space-md); }
  .import-record details { margin-top: var(--space-md); }
  select { max-width: 100%; }
</style>
