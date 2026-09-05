<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';

  export let title = 'Nothing here yet.';
  export let description = '';
  export let actionLabel = '';
  export let actionHref = '';
  export let icon: IconName = 'archive';
</script>

<div class="empty-state">
  <span class="empty-state__mark"><Icon name={icon} size={16} /></span>
  <h3>{title}</h3>
  {#if description}<p>{description}</p>{/if}
  {#if actionLabel && actionHref}<a class="button button--primary" href={actionHref}>{actionLabel}<Icon name="arrow" size={14} /></a>{/if}
</div>
