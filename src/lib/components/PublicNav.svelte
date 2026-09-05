<script lang="ts">
  import Icon from './Icon.svelte';
  import GitHubSignIn from './GitHubSignIn.svelte';

  export let user: { id: string; name?: string; image?: string | null; githubUsername?: string | null } | null = null;
  export let role = 'public';
  export let packages: Array<{ name: string; version?: string; channel?: string; architecture?: string }> = [];

  let searchOpen = false;
  let query = '';
  let dialog: HTMLDialogElement;

  $: filteredPackages = packages
    .filter((pkg) => !query || pkg.name.toLowerCase().includes(query.toLowerCase()))
    .slice(0, 8);
  $: userLabel = user?.githubUsername ? `@${user.githubUsername}` : user?.name || 'signed in';

  function openSearch() {
    searchOpen = true;
    setTimeout(() => dialog?.querySelector<HTMLInputElement>('input')?.focus(), 0);
  }

  function closeSearch() {
    searchOpen = false;
    query = '';
  }

  function packageHref(pkg: { name: string; channel?: string; architecture?: string }) {
    const params = new URLSearchParams();
    if (pkg.channel === 'dev') params.set('channel', 'dev');
    if (pkg.architecture === 'x86_64' || pkg.architecture === 'aarch64') params.set('architecture', pkg.architecture);
    const queryString = params.toString();
    return `/packages/${encodeURIComponent(pkg.name)}${queryString ? `?${queryString}` : ''}`;
  }

  function handleKeydown(event: KeyboardEvent) {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      searchOpen ? closeSearch() : openSearch();
    }

    if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes((event.target as HTMLElement)?.tagName)) {
      event.preventDefault();
      openSearch();
    }

    if (event.key === 'Escape' && searchOpen) closeSearch();
  }
</script>

<svelte:window on:keydown={handleKeydown} />

<header class="public-nav">
  <a class="brand" href="/" aria-label="OMAPKG home">
    <img class="brand__wordmark" src="/brand/omapkg-wordmark.svg" alt="OMAPKG" width="572" height="120" />
  </a>

  <button class="search-pill" type="button" aria-label="Search packages" on:click={openSearch}>
    <Icon name="search" size={16} />
    <span class="search-pill__label">Search packages</span>
    <kbd>Ctrl+K</kbd>
  </button>

  <nav class="public-nav__links" aria-label="Public navigation">
    <a href="/packages">Packages</a>
    <a href="/docs">Docs</a>
    <a href="/privacy">Privacy</a>
    {#if user && role !== 'public'}
      <a class="button" href="/maintain">Open workspace<Icon name="arrow" size={14} /></a>
    {:else if user}
      <span class="tag"><Icon name="user" size={13} />{userLabel}</span>
    {:else}
      <GitHubSignIn />
    {/if}
  </nav>
</header>

{#if searchOpen}
  <div class="cmdk-backdrop" role="presentation" on:click={closeSearch}></div>
  <dialog bind:this={dialog} class="cmdk-dialog" open aria-labelledby="search-title">
    <div class="cmdk-dialog__field">
      <Icon name="search" size={18} />
      <input id="search-title" bind:value={query} aria-label="Search package names" placeholder="Search package names…" />
      <button class="button button--quiet" type="button" aria-label="Close search" on:click={closeSearch}><kbd>Esc</kbd></button>
    </div>
    <div class="cmdk-dialog__results">
      {#if filteredPackages.length}
        <p class="cmdk-dialog__group">Packages</p>
        {#each filteredPackages as pkg}
          <a class="cmdk-dialog__result" href={packageHref(pkg)} on:click={closeSearch}>
            <span>{pkg.name}</span>
            <span class="timestamp">{pkg.version || pkg.channel || 'Open detail'}</span>
          </a>
        {/each}
      {:else if query}
        <div class="empty-state">
          <span class="empty-state__mark"><Icon name="search" size={16} /></span>
          <h3>No package matches: {query}</h3>
          <p>Package records appear after a reviewed release reaches the public catalogue.</p>
          <a class="button" href="/request" on:click={closeSearch}>Request a package<Icon name="arrow" size={14} /></a>
        </div>
      {:else}
        <p class="cmdk-dialog__group">Navigate</p>
        <a class="cmdk-dialog__result" href="/packages" on:click={closeSearch}><span>Browse packages</span><span class="timestamp">↵ open</span></a>
        <a class="cmdk-dialog__result" href="/request" on:click={closeSearch}><span>Request a package</span><span class="timestamp">↵ open</span></a>
        <a class="cmdk-dialog__result" href="/docs" on:click={closeSearch}><span>Read documentation</span><span class="timestamp">↵ open</span></a>
      {/if}
    </div>
    <div class="cmdk-dialog__foot"><span><kbd>/</kbd> or <kbd>Ctrl+K</kbd> open</span><span><kbd>Esc</kbd> close</span></div>
  </dialog>
{/if}
