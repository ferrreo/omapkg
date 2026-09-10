<script lang="ts">
  import GitHubSignIn from '$lib/components/GitHubSignIn.svelte';
  import Icon from '$lib/components/Icon.svelte';

  export let status: number;

  export let error: { message?: string };

  const titleFor = (status: number) => {
    if (status === 401) return 'Sign in required.';

    if (status === 403) return 'Access denied.';

    if (status === 404) return 'Page not found.';

    if (status === 503) return 'Service unavailable.';

    return 'Request failed.';
  };

  const descriptionFor = (status: number, message = '') => {
    if (status === 401) return 'GitHub sign-in is required for this workspace.';

    if (status === 403) return 'Your account does not have permission to open this workspace.';

    if (status === 404) return 'This URL does not point to a published page or package.';

    if (status === 503) return 'The service could not reach its data store. Try again in a moment.';

    return message || 'The request could not be completed.';
  };

  const iconFor = (status: number) => {
    if (status === 401) return 'lock';

    if (status === 404) return 'search';

    return 'activity';
  };

  $: title = titleFor(status);
  $: description = descriptionFor(status, error?.message);
</script>

<svelte:head><title>{status} · omapkg</title></svelte:head>

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="error-title">
    <div class="empty-state">
      <span class="empty-state__mark"><Icon name={iconFor(status)} size={16} /></span>
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
