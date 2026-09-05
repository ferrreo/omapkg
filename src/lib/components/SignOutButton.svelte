<script lang="ts">
  import Icon from './Icon.svelte';

  let busy = false;

  async function signOut() {
    busy = true;
    const response = await fetch('/api/auth/sign-out', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (response.ok) window.location.assign('/');
    busy = false;
  }
</script>

<button class="button button--quiet" type="button" disabled={busy} on:click={signOut}><Icon name="x" size={14} />{busy ? 'Signing out…' : 'Sign out'}</button>
