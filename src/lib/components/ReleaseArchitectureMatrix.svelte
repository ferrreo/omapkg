<script lang="ts">
  import StatusPill from './StatusPill.svelte';
  import { architectureLabel, releaseDate, type ReleaseCheck, type ReleaseRepository } from '$lib/release-workbench';
  import type { Architecture } from '$lib/model';

  export let architectures: Architecture[] = ['x86_64', 'aarch64'];
  export let repositories: ReleaseRepository[] = [];
  export let checks: ReleaseCheck[] = [];
  export let heading = 'Target evidence';
  export let matrixId = 'release-matrix-title';

  const repositoryFor = (architecture: Architecture) => repositories.find((item) => item.architecture === architecture);
  const checkFor = (architecture: Architecture) => checks.find((item) => item.architecture === architecture);
</script>

<section class="release-matrix" aria-labelledby="release-matrix-title">
  <h3 id={matrixId}>{heading}</h3>
  <div class="release-matrix__scroll" tabindex="-1" role="region" aria-label="Architecture release evidence">
    <table>
      <thead><tr><th scope="col">Target</th><th scope="col">Repository</th><th scope="col">Required checks</th><th scope="col">Last verified</th></tr></thead>
      <tbody>
        {#each architectures as architecture}
          <tr>
            <th scope="row">{architectureLabel(architecture)}</th>
            <td>
              {#if repositoryFor(architecture)}
                <StatusPill status={repositoryFor(architecture)?.state ?? 'unavailable'} />
                <span class="release-matrix__detail">{repositoryFor(architecture)?.packageCount === null || repositoryFor(architecture)?.packageCount === undefined ? 'Package count not recorded' : `${repositoryFor(architecture)?.packageCount} package${repositoryFor(architecture)?.packageCount === 1 ? '' : 's'}`}</span>
                {#if repositoryFor(architecture)?.databaseUrl && repositoryFor(architecture)?.signatureUrl}<span class="release-matrix__links"><a href={repositoryFor(architecture)?.databaseUrl}>Database</a><a href={repositoryFor(architecture)?.signatureUrl}>Signature</a></span>{/if}
              {:else}<span class="status status--unavailable">Unavailable</span><span class="release-matrix__detail">No published repository record.</span>{/if}
            </td>
            <td>
              {#if checkFor(architecture)}<StatusPill status={checkFor(architecture)?.status ?? 'pending'} label={checkFor(architecture)?.label ?? 'Pending'} />{#if checkFor(architecture)?.detail}<span class="release-matrix__detail">{checkFor(architecture)?.detail}</span>{/if}{:else}<span class="status status--pending">Pending</span><span class="release-matrix__detail">No target test record.</span>{/if}
            </td>
            <td class="timestamp">{releaseDate(checkFor(architecture)?.checkedAt ?? null)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .release-matrix { display: grid; gap: var(--space-sm); min-width: 0; }
  .release-matrix h3 { margin: 0; }
  .release-matrix__scroll { max-width: 100%; overflow-x: auto; }
  table { border-collapse: collapse; min-width: 46rem; width: 100%; }
  th, td { border-bottom: var(--border-width) solid var(--color-rule-soft); padding: var(--space-sm); text-align: left; vertical-align: top; }
  thead th { color: var(--color-text-muted); font-size: var(--text-xs); font-weight: 400; letter-spacing: .06em; text-transform: uppercase; }
  tbody th { color: var(--color-text-strong); font-weight: 400; }
  td { color: var(--color-text); font-size: var(--text-sm); min-width: 0; overflow-wrap: anywhere; }
  .release-matrix__detail { color: var(--color-text-muted); display: block; font-size: var(--text-xs); margin-top: var(--space-2xs); }
  .release-matrix__links { display: flex; flex-wrap: wrap; gap: var(--space-sm); margin-top: var(--space-2xs); }
</style>
