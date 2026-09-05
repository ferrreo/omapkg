<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  type ImageRecord = PageData['images'][number];
  $: images = (Array.isArray(data?.images) ? data.images : []) as ImageRecord[];
  $: user = data?.user || null;
  $: isAdmin = data?.role === 'admin';
  $: actorNames = ((data as unknown as { actorNames?: Record<string, string> })?.actorNames || {}) as Record<string, string>;
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string } : {};

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  function actorLabel(value: string) {
    return actorNames[value] || (value.startsWith('github:') ? 'GitHub user' : value);
  }
</script>

<svelte:head><title>Build images · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="images" {user}>
  <section class="maintainer-page" aria-labelledby="images-title">
    <header class="maintainer-page__head">
      <div>
        <span class="eyebrow">Digest pinned · per architecture · append only</span>
        <h1 id="images-title">Build images</h1>
        <p>Register the exact image a worker may use. Image identity stays fixed after registration; administrators control availability and the default for each architecture.</p>
      </div>
      <span class="tag tag--accent"><Icon name="lock" size={13} />{isAdmin ? 'admin controls' : 'read only'}</span>
    </header>

    {#if result.error}
      <div class="form-notice form-notice--danger" role="alert">{result.error}</div>
    {:else if result.success}
      <div class="notice-bar" role="status"><p>Build image change recorded in the audit log.</p><a href="/maintain/audit">Open audit<Icon name="arrow" size={14} /></a></div>
    {/if}

    <section class="workbench-panel" aria-labelledby="register-image-title">
      <div class="workbench-panel__head"><h2 id="register-image-title">Register an image</h2><span class="timestamp">disabled until enabled</span></div>
      <p class="prose">Use a complete registry reference with a SHA-256 digest. This form accepts no Docker commands, registry credentials, or mutable tags.</p>
      <form method="POST" action="?/register">
        <fieldset disabled={!isAdmin} style="border: 0; display: contents; padding: 0;">
          <div class="form-grid">
            <div class="field">
              <label for="image-label">Label</label>
              <input id="image-label" name="label" required maxlength="120" placeholder="Arch base-devel stable" />
              <span class="field__hint">Human-readable name for review and worker setup.</span>
            </div>
            <div class="field">
              <label for="image-architecture">Architecture</label>
              <select id="image-architecture" name="architecture" required>
                <option value="x86_64">x86_64 · AMD64</option>
                <option value="aarch64">aarch64 · ARM64</option>
              </select>
              <span class="field__hint">Defaults are selected separately for each architecture.</span>
            </div>
            <div class="field field--full">
              <label for="image-ref">Full registry image reference</label>
              <input id="image-ref" name="image_ref" required maxlength="512" spellcheck="false" placeholder="docker.io/library/archlinux:base-devel@sha256:…" aria-describedby="image-ref-hint" />
              <span id="image-ref-hint" class="field__hint">Lowercase registry path plus <code>@sha256:</code> and 64 hexadecimal characters.</span>
            </div>
            <div class="field">
              <label for="image-mirror">Mirror label</label>
              <select id="image-mirror" name="mirror" required>
                <option value="stable">stable</option>
                <option value="rc">rc</option>
                <option value="edge">edge</option>
                <option value="custom">custom</option>
              </select>
              <span class="field__hint">Describes source policy; it does not change the digest.</span>
            </div>
          </div>
          <div class="form-actions">
            <span class="field__hint">New records start disabled. Enable only after reviewing the manifest.</span>
            <button class="button button--primary" type="submit"><Icon name="plus" size={14} />Register image</button>
          </div>
        </fieldset>
      </form>
      {#if !isAdmin}<p class="field__hint" style="margin-top: var(--space-md)">Administrator access is required to register or change image settings.</p>{/if}
    </section>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="registered-images-title">
      <div class="workbench-panel__head"><h2 id="registered-images-title">Registered images</h2><span class="timestamp">{images.length} record{images.length === 1 ? '' : 's'}</span></div>
      {#if images.length}
        <div class="data-table-wrap">
          <table class="data-table">
            <thead><tr><th>Label</th><th>Image reference</th><th>Arch</th><th>Mirror</th><th>State</th><th>Created</th><th>Action</th></tr></thead>
            <tbody>
              {#each images as image}
                <tr>
                  <td>{image.label}<div class="timestamp">{image.id}</div></td>
                  <td><span class="hash">{image.image_ref}</span></td>
                  <td>{image.architecture}</td>
                  <td>{image.mirror}</td>
                  <td>
                    <div class="release-actions">
                      <span class={`tag ${image.enabled === 1 ? 'tag--positive' : 'tag--warning'}`}>{image.enabled === 1 ? 'enabled' : 'disabled'}</span>
                      {#if image.is_default === 1}<span class="tag tag--accent">default</span>{/if}
                    </div>
                  </td>
                  <td>{formatDate(image.created_at)}<div class="timestamp">{actorLabel(image.created_actor)}</div></td>
                  <td>
                    {#if isAdmin}
                      <div class="release-actions">
                        <form method="POST" action={image.enabled === 1 ? '?/disable' : '?/enable'}>
                          <input type="hidden" name="image_id" value={image.id} />
                          <button class="button" type="submit"><Icon name={image.enabled === 1 ? 'lock' : 'check'} size={14} />{image.enabled === 1 ? 'Disable' : 'Enable'}</button>
                        </form>
                        {#if image.enabled === 1 && image.is_default !== 1}
                          <form method="POST" action="?/setDefault"><input type="hidden" name="image_id" value={image.id} /><button class="button" type="submit"><Icon name="check" size={14} />Set default</button></form>
                        {/if}
                      </div>
                    {:else}
                      <span class="timestamp">admin only</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <EmptyState title="No build images registered." description="Register a digest-pinned image before a worker can receive a build policy. Reference links below describe possible inputs; they do not create records." icon="box" />
      {/if}
    </section>

    <section class="section section--tight" style="padding-inline: 0" aria-labelledby="image-reference-title">
      <div class="surface-grid">
        <article class="surface-panel" aria-labelledby="image-reference-title">
          <div class="surface-panel__top"><h2 id="image-reference-title">Reference inputs</h2><Icon name="book" size={20} /></div>
          <p>Use official documentation to inspect a candidate image, then register its full digest here. Arch build environments commonly use the <code>base</code>, <code>base-devel</code>, and <code>multilib-devel</code> package groups for AMD64.</p>
          <div class="surface-panel__meta"><a href="https://hub.docker.com/_/archlinux" rel="noreferrer">Official Arch Linux image</a><span>·</span><a href="https://wiki.archlinux.org/title/DeveloperWiki:Building_in_a_clean_chroot" rel="noreferrer">Clean chroot guidance</a></div>
        </article>
        <article class="surface-panel surface-panel--recipe">
          <div class="surface-panel__top"><h2>Omarchy build recipe</h2><Icon name="code" size={20} /></div>
          <p>The official recipe documents AMD64 and ARM mirrors. It is source guidance, not a published Omarchy registry image. Record the actual digest you inspect.</p>
          <div class="surface-panel__meta"><a href="https://github.com/omacom/omarchy-pkgs/blob/master/build/Dockerfile" rel="noreferrer">Open build/Dockerfile<Icon name="external" size={13} /></a></div>
        </article>
      </div>
    </section>

    {#if images.length}
      <section class="section section--tight" style="padding-inline: 0" aria-labelledby="local-builder-title">
        <article class="surface-panel surface-panel--recipe">
          <div class="surface-panel__top"><h2 id="local-builder-title">Local builder notes</h2><Icon name="terminal" size={20} /></div>
        <p>An image record exists. Keep local worker setup aligned with its registered digest and the repository's <code>docs/build-environment.md</code> reference.</p>
        </article>
      </section>
    {/if}
  </section>
</MaintainerShell>
