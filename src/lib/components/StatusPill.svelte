<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';

  export let status = '';
  export let label = '';

  const iconFor: Record<string, IconName> = {
    active: 'check',
    built: 'check',
    building: 'activity',
    cancelled: 'x',
    dev: 'clock',
    failed: 'x',
    generating: 'code',
    leased: 'play',
    pending: 'clock',
    queued: 'clock',
    rejected: 'x',
    review: 'lock',
    revoked: 'x',
    stable: 'check',
    succeeded: 'check',
    withdrawn: 'archive'
  };

  $: normalized = status.toLowerCase().replaceAll('_', '-');
  $: text = label || status.replaceAll('_', ' ');
  $: icon = iconFor[normalized] || 'activity';
</script>

<span class={`status status--${normalized}`}>
  <Icon name={icon} size={13} />
  <span>{text}</span>
</span>
