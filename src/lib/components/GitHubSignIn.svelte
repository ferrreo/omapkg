<script lang="ts">
  import Icon from './Icon.svelte';

  export let callbackURL = '/maintain';
  let busy = false;
  let error = '';

  async function signIn() {
    busy = true;
    error = '';
    try {
      const response = await fetch('/api/auth/sign-in/social', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'github', callbackURL })
      });
      const body = await response.json().catch(() => ({})) as { message?: string; url?: string };
      if (!response.ok) throw new Error(body.message || 'GitHub sign-in could not start.');
      if (body.url) window.location.assign(body.url);
      else window.location.assign(callbackURL);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'GitHub sign-in could not start.';
      busy = false;
    }
  }
</script>

<span class="sign-in-control">
  <button class="button button--primary" type="button" disabled={busy} on:click={signIn}>
    <Icon name="git" size={14} />{busy ? 'Connecting…' : 'Sign in'}
  </button>
  {#if error}<span class="sign-in-control__error" role="alert">{error}</span>{/if}
</span>
