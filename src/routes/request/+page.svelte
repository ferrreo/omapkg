<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import GitHubSignIn from '$lib/components/GitHubSignIn.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  $: user = data?.user || null;
  $: role = data?.role || 'public';
  const initialResult = form && typeof form === 'object' ? form as { message?: string; requestId?: string; values?: Record<string, string>; error?: string } : {};
  $: result = form && typeof form === 'object' ? form as { message?: string; requestId?: string; values?: Record<string, string>; error?: string } : {};
  let name = initialResult.values?.name || '';
  let upstreamUrl = initialResult.values?.upstream_url || '';
  let sourceKind = initialResult.values?.source_kind || 'git';
  let sourceKindManuallyChosen = Boolean(initialResult.values?.source_kind);
  let area = initialResult.values?.area || 'desktop';
  let description = initialResult.values?.description || '';
  const commonLicenses = ['MIT', 'Apache-2.0', 'GPL-3.0-or-later', 'BSD-2-Clause', 'BSD-3-Clause', 'LGPL-3.0-or-later', 'MPL-2.0'];
  const initialLicense = initialResult.values?.declared_license || '';
  let licenseChoice = initialLicense && (commonLicenses.includes(initialLicense) || ['proprietary', 'unknown'].includes(initialLicense)) ? initialLicense : initialLicense ? 'other' : '';
  let customLicense = licenseChoice === 'other' ? initialLicense : '';

  const downloadExtension = /(?:\.tar(?:\.[a-z0-9]+)?|\.tgz|\.tbz2?|\.txz|\.zip|\.deb|\.rpm|\.appimage|\.run)(?:[?#]|$)/i;

  function inferSourceKind() {
    if (sourceKindManuallyChosen || sourceKind !== 'git' || !downloadExtension.test(upstreamUrl.trim())) return;
    sourceKind = 'archive';
  }
</script>

<svelte:head>
  <title>Request a package · omapkg</title>
  <meta name="description" content="Request software from a Git repository or direct source or binary download." />
</svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <section class="section site-width--narrow" aria-labelledby="request-title">
    <div class="section__head">
      <div>
        <h1 id="request-title">Request a package</h1>
      </div>
      <p>Give omapkg a package name and upstream URL. The factory generates the recipe, and maintainers review it before any build.</p>
    </div>

    {#if !user}
      <div class="notice-bar">
        <p>Sign in with GitHub before submitting. Your request will be tied to an authenticated account for feedback and history.</p>
        <GitHubSignIn callbackURL="/request" />
      </div>
    {/if}

    {#if result.requestId || result.message}
      <div class="notice-bar">
        <div><strong>Request recorded.</strong><p>{result.requestId ? `Request ${result.requestId} is now in the area queue.` : result.message || 'Your request is now in the area queue.'}</p></div>
        {#if user && role !== 'public'}<a class="button" href="/maintain">View workspace<Icon name="arrow" size={14} /></a>{:else}<a class="button" href="/packages">Browse packages<Icon name="arrow" size={14} /></a>{/if}
      </div>
    {/if}

    {#if result.error}
      <div class="form-notice form-notice--danger" role="alert">{result.error}</div>
    {/if}

    <form class="workbench-panel" method="POST">
      <div class="form-grid">
        <div class="field">
          <label for="name">Package name</label>
          <input id="name" name="name" bind:value={name} required maxlength="128" autocomplete="off" placeholder="package-name" aria-describedby="name-hint" />
          <span id="name-hint" class="field__hint">Use the name users will type into Arch tooling.</span>
        </div>

        <div class="field">
          <label for="area">Area</label>
          <select id="area" name="area" bind:value={area} required>
            <option value="desktop">Desktop</option>
            <option value="development">Development</option>
            <option value="gaming">Gaming</option>
            <option value="multimedia">Multimedia</option>
            <option value="productivity">Productivity</option>
            <option value="system">System</option>
          </select>
          <span class="field__hint">This chooses the first maintainer queue.</span>
        </div>

        <div class="field field--full">
          <label for="description">Package description</label>
          <textarea id="description" name="description" bind:value={description} required maxlength="500" aria-describedby="description-hint" placeholder="What is this package for?"></textarea>
          <span id="description-hint" class="field__hint">Describe the software in up to 500 characters. The factory refines this into final public package text after inspection.</span>
        </div>

        <div class="field field--full">
          <label for="upstream-url">Upstream URL</label>
          <input id="upstream-url" name="upstream_url" type="url" bind:value={upstreamUrl} required maxlength="2048" placeholder={sourceKind === 'git' ? 'https://git.example.org/project/repository' : 'https://downloads.example.org/software.tar.gz'} on:blur={inferSourceKind} aria-describedby="url-hint" />
          <span id="url-hint" class="field__hint">Git hosts and direct downloads are accepted. Mutable refs are resolved before build.</span>
        </div>

        <div class="field">
          <label for="source-kind">Input type</label>
          <select id="source-kind" name="source_kind" bind:value={sourceKind} on:change={() => (sourceKindManuallyChosen = true)} required aria-describedby="source-kind-hint">
            <option value="git">Git repository</option>
            <option value="archive">Download (source or binary package)</option>
          </select>
          <span id="source-kind-hint" class="field__hint">Downloads can be tar, zip, deb, rpm, AppImage, or .run. The inspector records the format and immutable byte digest.</span>
        </div>

        <div class="field">
          <label for="declared-license-choice">Upstream license</label>
          <select id="declared-license-choice" bind:value={licenseChoice} required aria-describedby="declared-license-hint">
            <option value="" disabled>Choose a license</option>
            {#each commonLicenses as license}<option value={license}>{license}</option>{/each}
            <option value="proprietary">Proprietary</option>
            <option value="unknown">Not sure</option>
            <option value="other">Other (SPDX expression)</option>
          </select>
          {#if licenseChoice === 'other'}
            <label class="sr-only" for="declared-license">SPDX license expression</label>
            <input id="declared-license" name="declared_license" bind:value={customLicense} required maxlength="256" placeholder="LicenseRef-Example OR MIT" aria-describedby="declared-license-hint" />
          {:else}
            <input type="hidden" name="declared_license" value={licenseChoice} />
          {/if}
          <span id="declared-license-hint" class="field__hint">Tell maintainers what upstream declares. Factory verification is recorded separately.</span>
        </div>
      </div>

      <div class="form-actions">
        <p class="field__hint">You do not upload a PKGBUILD or provide build credentials. Review happens before generation and again before build.</p>
        <button class="button button--primary" type="submit">Create request<Icon name="arrow" size={14} /></button>
      </div>
    </form>
  </section>

  <section class="section site-width--narrow">
    <div class="surface-grid">
      <article class="surface-panel"><div class="surface-panel__top"><h2>Next steps</h2><Icon name="activity" size={20} /></div><p>Area maintainers validate the request, the inspector records the upstream input, and the factory produces a diff. The requestor's feedback is recorded as evidence; only maintainers decide promotion.</p></article>
      <article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>Input stays pinned</h2><Icon name="lock" size={20} /></div><p>Online inspection records redirects, format, source hashes, dependency inputs, and build policy before an offline worker receives a lease.</p></article>
    </div>
  </section>

  <footer class="site-footer"><p>omapkg · request flow</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/packages">Packages</a><a href="/docs/security">Security</a><a href="/">Home</a></nav></footer>
</main>
