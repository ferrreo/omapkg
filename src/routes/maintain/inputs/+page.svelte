<script lang="ts">
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import FrozenInputUpload from '$lib/components/FrozenInputUpload.svelte';
  import { enhance } from '$app/forms';
  import type { PageData, ActionData } from './$types';

  export let data: PageData;

 export let form: ActionData;
</script>
<svelte:head><title>Frozen build inputs · omapkg</title></svelte:head>
<MaintainerShell active="inputs" user={data.user}>
  <section class="maintainer-page">
    <header class="maintainer-page__head"><div><h1>Frozen build inputs</h1><p>Retain exact package closures, review their sources and keys, then bind them to a native build.</p></div><a class="button" href="/maintain/cohorts">Build cohorts</a></header>
    <p class="notice-bar">Bootstrap seeds authorize private rebuilds. Owned input locks use signed native outputs. Publication still requires complete cohort qualification and release approval.</p>
    {#if form?.error}<p class="form-notice form-notice--danger" role="alert">{form.error}</p>{:else if form?.success}<p class="notice-bar" role="status">Input origin revoked. Affected active leases are fenced.</p>{/if}
    <form class="filter-bar" method="GET"><div class="field"><label for="input-search">Find package</label><input id="input-search" name="search" value={data.search} maxlength="128" /></div><button class="button" type="submit">Search</button></form>
    <section class="workbench-panel"><h2>Input locks</h2>{#if data.locks.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package / cohort</th><th>Target</th><th>Inputs</th><th>Reviews</th><th>Use</th></tr></thead><tbody>{#each data.locks as lock}<tr><td><a href={`/maintain/inputs/${lock.sha256}`}>{lock.pkgbase}</a><div class="timestamp">{lock.title} · revision {lock.cohort_revision}</div></td><td>{lock.architecture}</td><td>{lock.purpose} · {lock.package_count} package records<div class="timestamp">{(lock.transfer_bytes / 1024 ** 2).toFixed(1)} MiB retained for execution</div></td><td>{lock.review_count} / 2 recorded</td><td>{lock.status === 'preparing' ? 'Upload incomplete' : lock.selected ? 'Selected' : 'Awaiting selection'}</td></tr>{/each}</tbody></table></div>{:else}<p>No input locks match. Upload a capture for a recipe in a current cohort.</p>{/if}</section>
    {#if data.canManage}<section class="workbench-panel"><h2>Upload retained inputs</h2><FrozenInputUpload candidates={data.candidates} /></section>{/if}
    <section class="workbench-panel"><h2>Retained native packages</h2><p>Package bytes and native build statement must both be signed before retention. Each consuming lock also rechecks the complete input ancestry.</p>{#if data.nativeInputs.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Native build</th><th>Authority</th><th>Origin</th></tr></thead><tbody>{#each data.nativeInputs as input}{@const pkg = JSON.parse(input.package_json)}<tr><td>{pkg.name}</td><td>{pkg.version} · {pkg.architecture}</td><td><a href={`/maintain/builds/${input.build_id}`}>Attempt {input.attempt}</a></td><td>{input.eligible ? 'Source reviews current' : 'Revoked or authority changed'}{#if input.revoked_at}<p>{input.revoke_reason}</p>{:else if data.canManage && ['admin', 'security'].includes(data.role)}<details><summary>Revoke this build origin</summary><form method="POST" action="?/revoke" use:enhance><input type="hidden" name="digest" value={input.package_sha256} /><input type="hidden" name="origin" value={input.origin_evidence} /><div class="field"><label for={`reason-${input.package_sha256}-${input.origin_evidence}`}>Revocation reason</label><input id={`reason-${input.package_sha256}-${input.origin_evidence}`} name="reason" required maxlength="2000" /></div><button class="button button--danger" type="submit">Revoke build origin</button></form></details>{/if}</td><td><a href={`/api/maintain/inputs/objects/${input.origin_evidence}`}>Download origin proof</a></td></tr>{/each}</tbody></table></div>{:else}<p>No native packages retained yet. Open a completed frozen build to sign and retain its outputs.</p>{/if}</section>
  </section>
</MaintainerShell>
