<script lang="ts">
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  const defaultTeams = ['desktop', 'development', 'gaming', 'multimedia', 'productivity', 'system', 'security', 'admin'] as const;
  type TeamName = (typeof defaultTeams)[number];
  type MemberRecord = { accountId: string; github_username: string; avatar_url?: string | null; team: string; canRevoke: boolean };
  type UserSuggestion = { username: string; name?: string | null; avatarUrl?: string | null };
  type MemberGroup = { accountId: string; username: string; members: MemberRecord[] };
  type TeamData = { teams?: unknown; members?: unknown; suggestions?: unknown };

  $: raw = data as unknown as TeamData;
  $: teams = Array.isArray(raw.teams) ? raw.teams.filter((value): value is TeamName => isTeamName(value)) : [...defaultTeams];
  $: members = Array.isArray(raw.members) ? raw.members.map(normalizeMember).filter((member): member is MemberRecord => member !== null) : [];
  $: suggestions = Array.isArray(raw.suggestions) ? raw.suggestions.filter(isSuggestion) : [];
  $: memberGroups = groupMembers(members);
  $: user = data?.user || null;
  $: isAdmin = data?.role === 'admin';
  $: result = form && typeof form === 'object' ? form as { success?: boolean; error?: string } : {};

  let githubUsername = '';
  let selectedTeams: string[] = [];
  let lookupState: 'idle' | 'checking' | 'valid' | 'invalid' = 'idle';
  let lookupMessage = '';
  let validationSequence = 0;

  const teamLabels: Record<TeamName, string> = {
    desktop: 'Desktop', development: 'Development', gaming: 'Gaming', multimedia: 'Multimedia',
    productivity: 'Productivity', system: 'System', security: 'Security', admin: 'Admin'
  };
  const teamDescriptions: Record<TeamName, string> = {
    desktop: 'Review desktop package requests.',
    development: 'Review development package requests.',
    gaming: 'Review gaming package requests.',
    multimedia: 'Review multimedia package requests.',
    productivity: 'Review productivity package requests.',
    system: 'Review system package requests.',
    security: 'Review security gates across every area.',
    admin: 'Manage platform and team settings; includes Security.'
  };

  function isTeamName(value: unknown): value is TeamName {
    return typeof value === 'string' && (defaultTeams as readonly string[]).includes(value);
  }

  function isSuggestion(value: unknown): value is UserSuggestion {
    return Boolean(value) && typeof value === 'object' && typeof (value as Record<string, unknown>).username === 'string';
  }

  function normalizeMember(value: unknown): MemberRecord | null {
    if (!value || typeof value !== 'object') return null;
    const row = value as Record<string, unknown>;
    if (typeof row.accountId !== 'string' || typeof row.github_username !== 'string') return null;
    const team = typeof row.team === 'string' ? row.team : typeof row.area === 'string' ? row.area : '';
    if (!team) return null;
    return { accountId: row.accountId, github_username: row.github_username, avatar_url: typeof row.avatar_url === 'string' ? row.avatar_url : null, team, canRevoke: row.canRevoke === true };
  }

  function groupMembers(rows: MemberRecord[]): MemberGroup[] {
    const grouped = new Map<string, MemberGroup>();
    for (const member of rows) {
      const group = grouped.get(member.accountId) || { accountId: member.accountId, username: member.github_username, members: [] };
      group.members.push(member);
      if (group.username === 'GitHub user' && member.github_username !== 'GitHub user') group.username = member.github_username;
      grouped.set(member.accountId, group);
    }
    return [...grouped.values()];
  }

  function teamLabel(value: string) {
    return isTeamName(value) ? teamLabels[value] : value;
  }

  function memberActionNote(member: MemberRecord) {
    return member.team === 'admin' ? 'Last administrator' : 'profile unavailable';
  }

  async function validateUsername() {
    const username = githubUsername.trim().replace(/^@/, '');
    if (!username || !isAdmin) {
      validationSequence += 1;
      lookupState = 'idle';
      lookupMessage = '';
      return;
    }
    const sequence = ++validationSequence;
    lookupState = 'checking';
    lookupMessage = 'Checking GitHub…';
    try {
      const response = await fetch(`/api/admin/github-users?username=${encodeURIComponent(username)}`, { headers: { Accept: 'application/json' } });
      const body = await response.json().catch(() => ({})) as { exists?: boolean; username?: string; name?: string | null; error?: string };
      if (sequence !== validationSequence || githubUsername.trim().replace(/^@/, '') !== username) return;
      if (!response.ok || body.exists !== true || !body.username) throw new Error(body.error || 'GitHub user was not found.');
      githubUsername = body.username;
      lookupState = 'valid';
      lookupMessage = body.name ? `Verified ${body.username} · ${body.name}` : `Verified ${body.username}`;
    } catch (cause) {
      if (sequence !== validationSequence || githubUsername.trim().replace(/^@/, '') !== username) return;
      lookupState = 'invalid';
      lookupMessage = cause instanceof Error ? cause.message : 'GitHub user could not be verified.';
    }
  }

  function usernameChanged() {
    validationSequence += 1;
    lookupState = 'idle';
    lookupMessage = '';
  }
</script>

<svelte:head><title>Team · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="team" {user}>
  <section class="maintainer-page" aria-labelledby="team-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Verified GitHub users · team access</span><h1 id="team-title">Maintainer team</h1><p>Grant one or more teams by verified GitHub username. Security reviews every area; Admin also manages platform and team settings.</p></div><span class="tag tag--accent"><Icon name="shield" size={13} />{isAdmin ? 'admin action' : 'read only'}</span></header>

    {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success}<div class="notice-bar" role="status"><p>Team change recorded in the audit log.</p><a href="/maintain/audit">Open audit<Icon name="arrow" size={14} /></a></div>{/if}

    <section class="workbench-panel" aria-labelledby="grant-title"><div class="workbench-panel__head"><h2 id="grant-title">Grant team access</h2><span class="timestamp">verified username</span></div><form class="team-grant-form" method="POST" action="?/grant"><fieldset disabled={!isAdmin} class="team-grant-form__fields"><div class="field"><label for="github-username">GitHub username</label><input id="github-username" name="github_username" bind:value={githubUsername} list="known-github-users" required autocomplete="off" placeholder="octocat" on:blur={validateUsername} on:input={usernameChanged} aria-describedby="github-username-hint" aria-invalid={lookupState === 'invalid'} aria-busy={lookupState === 'checking'} /><datalist id="known-github-users">{#each suggestions as suggestion}<option value={suggestion.username}>{suggestion.name ? `${suggestion.name} · @${suggestion.username}` : `@${suggestion.username}`}</option>{/each}</datalist><span id="github-username-hint" aria-live="polite" class={`field__hint ${lookupState === 'valid' ? 'field__hint--success' : lookupState === 'invalid' ? 'field__hint--danger' : ''}`}>{lookupMessage || 'GitHub verifies this profile before access is granted.'}</span></div><fieldset class="team-checkboxes" aria-describedby="team-selection-hint"><legend>Teams</legend>{#each teams as team}<label class="team-option"><input type="checkbox" name="teams" value={team} bind:group={selectedTeams} /><span class="team-option__copy"><strong>{teamLabel(team)}</strong><span>{teamDescriptions[team]}</span></span></label>{/each}</fieldset><span id="team-selection-hint" class="field__hint">Select one or more teams. Admin includes Security and platform/team management.</span></fieldset><div class="team-grant-form__actions"><span class="field__hint">{selectedTeams.length} team{selectedTeams.length === 1 ? '' : 's'} selected</span><button class="button button--primary" type="submit" disabled={!isAdmin || lookupState !== 'valid' || selectedTeams.length === 0}><Icon name="plus" size={14} />Grant access</button></div></form>{#if !isAdmin}<p class="field__hint" style="margin-top: var(--space-md)">Administrator access is required to change team memberships.</p>{/if}</section>

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="members-title"><div class="workbench-panel__head"><h2 id="members-title">Current memberships</h2><span class="timestamp">{memberGroups.length} user{memberGroups.length === 1 ? '' : 's'} · {members.length} team{members.length === 1 ? '' : 's'}</span></div>{#if memberGroups.length}<div class="data-table-wrap"><table class="data-table data-table--members"><thead><tr><th>GitHub user</th><th>Teams</th><th>Action</th></tr></thead><tbody>{#each memberGroups as group}<tr><td>{group.username}</td><td><div class="team-members">{#each group.members as member}<span class="tag">{teamLabel(member.team)}</span>{/each}</div></td><td>{#if isAdmin}<div class="team-actions">{#each group.members as member}{#if member.canRevoke}<form method="POST" action="?/revoke"><input type="hidden" name="github_username" value={group.username} /><input type="hidden" name="expected_github_id" value={group.accountId} /><input type="hidden" name="team" value={member.team} /><button class="button" type="submit" aria-label={`Revoke ${teamLabel(member.team)} access for ${group.username}`}><Icon name="x" size={14} />Revoke {teamLabel(member.team)}</button></form>{:else}<span class="timestamp">{memberActionNote(member)}</span>{/if}{/each}</div>{:else}<span class="timestamp">Read only</span>{/if}</td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No team memberships." description="Grant a verified GitHub user one or more teams before they can review requests or manage the platform." icon="user" />{/if}</section>

    <section class="section section--tight" style="padding-inline: 0"><article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>Team permissions</h2><Icon name="log" size={20} /></div><p>Area teams review their queue. Security can review every area and approve security gates. Admin includes Security and manages platform and team settings. Grants and revokes are recorded in the audit log.</p></article></section>
  </section>
</MaintainerShell>
