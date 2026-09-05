<script lang="ts">
  import type { Release } from '../model';
  import Icon from './Icon.svelte';
  import StatusPill from './StatusPill.svelte';

  export let release: Release & { description?: string | null };

  $: packageHref = `/packages/${encodeURIComponent(release.name)}?channel=${release.channel === 'dev' ? 'dev' : 'stable'}&architecture=${encodeURIComponent(release.architecture)}`;
  $: surfaceLabel = release.surface === 'binary' ? 'Surface A · binary' : 'Surface B · recipe';
</script>

<a class="package-row" href={packageHref}>
  <span>
    <span class="package-row__name">{release.name}</span>
    <span class="package-row__sub">{release.version}</span>
    {#if release.description}<span class="package-row__description">{release.description}</span>{/if}
  </span>
  <span class="package-row__meta">{surfaceLabel}</span>
  <span class="package-row__meta">{release.architecture}</span>
  <StatusPill status={release.channel} />
  <Icon name="arrow" size={16} />
</a>
