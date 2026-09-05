<script lang="ts">
  import GitHubSignIn from '$lib/components/GitHubSignIn.svelte';
  import Icon from '$lib/components/Icon.svelte';

  export let status: number;
  export let error: { message?: string };

  $: title = status === 401 ? 'Sign in required.' : status === 403 ? 'Access denied.' : status === 404 ? 'Page not found.' : status === 503 ? 'Service unavailable.' : 'Request failed.';
  $: description = status === 401 ? 'GitHub sign-in is required for this workspace.' : status === 403 ? 'Your account does not have permission to open this workspace.' : status === 404 ? 'This URL does not point to a published page or package.' : status === 503 ? 'The service could not reach its data store. Try again in a moment.' : error?.message || 'The request could not be completed.';
</script>

<svelte:head><title>{status} · omapkg</title></svelte:head>

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="error-title">
    <div class="empty-state">
      <span class="empty-state__mark"><Icon name={status === 401 ? 'lock' : status === 404 ? 'search' : 'activity'} size={16} /></span>
      <span class="eyebrow">HTTP {status}</span>
      <h1 id="error-title">{title}</h1>
      <p>{description}</p>
      <div class="action-row">
        {#if status === 401}<GitHubSignIn callbackURL="/maintain" />{/if}
        <a class="button button--primary" href="/packages">Browse packages<Icon name="arrow" size={14} /></a>
        <a class="button button--quiet" href="/">Go home</a>
      </div>
    </div>
  </section>
</main>
