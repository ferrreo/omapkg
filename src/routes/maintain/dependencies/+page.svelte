<script lang="ts">
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import type { PageData } from './$types';

  export let data: PageData;
</script>
<svelte:head><title>Dependency admission · omapkg</title></svelte:head>
<MaintainerShell active="dependencies" user={data.user}>
  <section class="maintainer-page">
    <header class="maintainer-page__head"><div><h1>Dependency proposals</h1><p>Missing providers become draft OPR packages. Review their source and affected parents before admitting packaging work.</p></div><a class="button" href="/maintain/requests?status=blocked">Blocked requests</a></header>
    <p class="notice-bar">AUR/ALARM references do not authorize dependency installation. Admission creates a pending package request; parents stay blocked until reviewed, compatible outputs exist.</p>
    <form method="GET" class="filter-bar"><div class="field"><label for="proposal-status">Decision state</label><select id="proposal-status" name="status" value={data.status}><option value="proposed">Awaiting decision</option><option value="admitted">Admitted for packaging</option><option value="declined">Declined</option><option value="superseded">Earlier revisions</option></select></div><button class="button" type="submit">Show proposals</button></form>
    {#if data.proposals.length}<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Required provider</th><th>Target</th><th>Blocked parents</th><th>Source review</th><th>State</th></tr></thead><tbody>{#each data.proposals as proposal}<tr><td><a href={`/maintain/dependencies/${proposal.id}`}>{proposal.manifest.relation}</a><div class="timestamp">Proposal revision {proposal.revision}</div></td><td>{proposal.manifest.architecture}</td><td>{proposal.parents}</td><td>{proposal.manifest.upstreamUrl ? proposal.manifest.origin : 'Authoritative source needed'}</td><td>{proposal.status === 'admitted' ? 'Admitted; normal package gates apply' : proposal.status}{#if proposal.decision_reason}<p>{proposal.decision_reason}</p>{/if}</td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No proposals in this state." description="A missing dependency reported by the factory or worker creates a shared draft. Existing decisions remain in history." />{/if}
    {#if data.proposals.length === 50}<a class="button" href={`?${new URLSearchParams({ status: data.status, after: data.proposals.at(-1)!.id })}`}>Next proposals</a>{/if}
  </section>
</MaintainerShell>
