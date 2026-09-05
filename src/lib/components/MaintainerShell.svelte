<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';
  import SignOutButton from './SignOutButton.svelte';

  export let active = 'queue';
  export let user: { id: string; name?: string; image?: string | null; githubUsername?: string | null } | null = null;

  const links: Array<{ href: string; label: string; key: string; icon: IconName }> = [
    { href: '/maintain', label: 'Queue', key: 'queue', icon: 'archive' },
    { href: '/maintain/workers', label: 'Workers', key: 'workers', icon: 'server' },
    { href: '/maintain/images', label: 'Images', key: 'images', icon: 'box' },
    { href: '/maintain/releases', label: 'Releases', key: 'releases', icon: 'package' },
    { href: '/maintain/audit', label: 'Audit', key: 'audit', icon: 'log' },
    { href: '/maintain/team', label: 'Team', key: 'team', icon: 'user' }
  ];

  const titles: Record<string, string> = {
    audit: 'Audit log',
    images: 'Build images',
    queue: 'Maintainer workspace',
    releases: 'Release batches',
    requests: 'Request review',
    workers: 'Worker fleet',
    team: 'Maintainer team'
  };

  $: activeKey = active === 'requests' ? 'queue' : active;
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
    <slot />
  </div>
</div>
