<script lang="ts">
  import Icon from './Icon.svelte';

  export let value = '';
  export let label = 'Copy';
  let copied = false;
  let timer: ReturnType<typeof setTimeout>;

  async function copy() {
    if (!value || typeof navigator === 'undefined' || !navigator.clipboard) return;
    await navigator.clipboard.writeText(value);
    copied = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = false), 2500);
  }
</script>

<button class="button button--quiet" type="button" aria-live="polite" on:click={copy}>
  <Icon name={copied ? 'check' : 'file'} size={14} />
  {copied ? 'Copied' : label}
</button>
