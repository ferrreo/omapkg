<script lang="ts">
  import FactoryDossier from '$lib/components/FactoryDossier.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { PageData } from './$types';

  export let data: PageData;

  $: user = data?.user || null;
</script>

<svelte:head><title>Factory dossier · maintainer · omapkg</title></svelte:head>
<MaintainerShell active="queue" {user}>
  <section class="maintainer-page" aria-label="Factory dossier">
    <FactoryDossier dossier={data.dossier} runUrl={data.runUrl} jsonUrl={`/api/maintain/dossiers/${encodeURIComponent(data.dossier.id)}`} markdownUrl={`/api/maintain/dossiers/${encodeURIComponent(data.dossier.id)}?format=markdown`} />
  </section>
</MaintainerShell>
