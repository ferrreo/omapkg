<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';
  import SignOutButton from './SignOutButton.svelte';

  export let active = 'queue';
  export let user: { id: string; name?: string; image?: string | null; githubUsername?: string | null } | null = null;

  const links: Array<{ href: string; label: string; key: string; icon: IconName }> = [
    { href: '/maintain', label: 'Inbox', key: 'queue', icon: 'archive' },
    { href: '/maintain/catalog', label: 'Catalog', key: 'catalog', icon: 'package' },
    { href: '/maintain/cohorts', label: 'Cohorts', key: 'cohorts', icon: 'box' },
    { href: '/maintain/releases', label: 'Releases', key: 'releases', icon: 'package' },
    { href: '/maintain/workers', label: 'Operations', key: 'operations', icon: 'server' },
    { href: '/maintain/audit', label: 'Audit', key: 'audit', icon: 'log' },
  ];
  const sections: Record<string, Array<{ href: string; label: string; key: string }>> = {
    queue: [{ href: '/maintain', label: 'Review queue', key: 'queue' }, { href: '/maintain/dependencies', label: 'Dependency proposals', key: 'dependencies' }],
    catalog: [{ href: '/maintain/catalog', label: 'Ownership policies', key: 'catalog' }, { href: '/maintain/imports', label: 'Imports and matching', key: 'imports' }, { href: '/maintain/inputs', label: 'Frozen build inputs', key: 'inputs' }],
    operations: [{ href: '/maintain/workers', label: 'Workers', key: 'workers' }, { href: '/maintain/images', label: 'Images', key: 'images' }, { href: '/maintain/team', label: 'Team access', key: 'team' }],
  };

  const titles: Record<string, string> = {
    catalog: 'Catalog ownership',
    imports: 'Repository imports',
    inputs: 'Frozen build inputs',
    dependencies: 'Dependency admission',
    cohorts: 'Build cohorts',
    audit: 'Audit log',
    images: 'Build images',
    queue: 'Maintainer workspace',
    releases: 'Release batches',
    requests: 'Request review',
    workers: 'Worker fleet',
    team: 'Maintainer team'
  };

  $: activeKey = ['requests', 'dependencies'].includes(active) ? 'queue' : ['imports', 'inputs'].includes(active) ? 'catalog' : ['workers', 'images', 'team'].includes(active) ? 'operations' : active;
  $: title = titles[active] || 'Maintainer workspace';
  $: userLabel = user?.githubUsername ? `@${user.githubUsername}` : user?.name || 'Signed-in maintainer';
</script>

<div class="maintainer-shell">
  <aside class="maintainer-rail">
    <a class="brand" href="/" aria-label="OMAPKG home">
      <img class="brand__wordmark" src="/brand/omapkg-wordmark.svg" alt="OMAPKG" width="572" height="120" />
    </a>

    <nav class="maintainer-rail__nav" aria-label="Maintainer navigation">
      {#each links as link}
        <a class:is-active={activeKey === link.key} class="maintainer-rail__link" href={link.href} aria-current={activeKey === link.key ? 'page' : undefined}>
          <Icon name={link.icon} size={16} />
          <span>{link.label}</span>
        </a>
      {/each}
      <a class="maintainer-rail__link" href="/packages"><Icon name="external" size={16} /><span>Public catalog</span></a>
    </nav>

    <div class="maintainer-rail__foot">
      <span class="timestamp">signed in as</span>
      <span>{userLabel}</span>
      <SignOutButton />
    </div>
  </aside>

  <div class="maintainer-main">
    <header class="maintainer-topbar">
      <span class="maintainer-topbar__title">{title}</span>
      <span class="tag tag--accent"><Icon name="shield" size={13} />omapkg / maintain</span>
    </header>
    {#if sections[activeKey]}<nav class="maintainer-section-nav" aria-label={`${links.find((link) => link.key === activeKey)?.label ?? 'Workspace'} sections`}>{#each sections[activeKey] as section}<a href={section.href} aria-current={active === section.key || (active === 'requests' && section.key === 'queue') ? 'page' : undefined}>{section.label}</a>{/each}</nav>{/if}
    <slot />
  </div>
</div>

<style>
  .maintainer-section-nav { display: flex; justify-content: center; flex-wrap: wrap; gap: 1rem; margin-block: 1rem; padding-inline: 1rem; }
  .maintainer-section-nav a[aria-current="page"] { font-weight: 700; text-decoration: underline; }
</style>
