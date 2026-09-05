<script lang="ts">
  import CopyButton from '$lib/components/CopyButton.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import MaintainerShell from '$lib/components/MaintainerShell.svelte';
  import StatusPill from '$lib/components/StatusPill.svelte';
  import type { Worker } from '$lib/model';
  import type { ActionData, PageData } from './$types';

  export let data: PageData;
  export let form: ActionData;

  type FleetWorker = Worker & { active_leases?: number | null };
  type WorkerState = 'active' | 'draining' | 'paused' | 'revoked' | 'archived';
  $: workers = (Array.isArray(data?.workers) ? data.workers : []) as FleetWorker[];
  $: user = data?.user || null;
  $: canManage = Boolean(data?.canManage);
  $: includeArchived = Boolean(data?.includeArchived);
  $: result = form && typeof form === 'object' ? form as { token?: string; expiresAt?: number; error?: string; success?: boolean } : {};
  $: enrollmentToken = result.token || '';
  $: enrollmentExpires = result.expiresAt || null;

  function formatDate(value: number | null | undefined) {
    return value ? new Date(value * 1000).toISOString().slice(0, 16).replace('T', ' ') : 'Never';
  }

  function activeLeases(worker: FleetWorker) {
    const value = Number(worker.active_leases ?? 0);
    return Number.isSafeInteger(value) && value > 0 ? value : 0;
  }

  function capabilities(value: string | null | undefined) {
    if (!value) return [];
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string' && item.length > 0) : [];
    } catch {
      return [];
    }
  }

  function workerState(worker: FleetWorker): WorkerState {
    if (worker.removed_at) return 'archived';
    if (worker.status === 'revoked') return 'revoked';
    if (worker.paused_at || worker.accepting_jobs === 0) return activeLeases(worker) > 0 ? 'draining' : 'paused';
    return 'active';
  }

  function stateLabel(state: WorkerState) {
    return { active: 'Active', draining: 'Draining', paused: 'Paused / Drained', revoked: 'Revoked', archived: 'Archived' }[state];
  }

  function pillStatus(state: WorkerState) {
    return { active: 'active', draining: 'leased', paused: 'pending', revoked: 'revoked', archived: 'withdrawn' }[state];
  }
</script>

<svelte:head><title>Worker fleet · maintainer · omapkg</title></svelte:head>

<MaintainerShell active="workers" {user}>
  <section class="maintainer-page" aria-labelledby="workers-title">
    <header class="maintainer-page__head"><div><span class="eyebrow">Outbound HTTPS · scoped leases · no signing key</span><h1 id="workers-title">Worker fleet</h1><p>Workers receive one job lease, build offline in a disposable environment, and upload attestations. Their identity is revocable.</p></div></header>

    {#if enrollmentToken}
      <div class="notice-bar"><div><strong>Enrollment token created.</strong><p>Copy it now. It expires {enrollmentExpires ? formatDate(enrollmentExpires) : 'soon'} and will not be shown again.</p><pre class="code-block">{enrollmentToken}</pre></div><CopyButton value={enrollmentToken} label="Copy token" /></div>
    {/if}
    {#if result.error}<div class="form-notice form-notice--danger" role="alert">{result.error}</div>{:else if result.success && !enrollmentToken}<div class="notice-bar" role="status"><p>Worker action recorded in the audit log.</p><a href="/maintain/audit">Open audit<Icon name="arrow" size={14} /></a></div>{/if}

    {#if canManage}
      <section class="workbench-panel" aria-labelledby="enroll-title"><div class="workbench-panel__head"><h2 id="enroll-title">Enroll Linux host</h2><span class="timestamp">single-use token</span></div><form class="form-actions" method="POST" action="?/enroll"><div class="field"><label for="architecture">Architecture</label><select id="architecture" name="architecture" required><option value="x86_64">x86_64</option><option value="aarch64">aarch64</option></select></div><p class="field__hint">Create the Ed25519 key locally on the host. The platform stores the public key only.</p><button class="button button--primary" type="submit"><Icon name="plus" size={14} />Create enrollment token</button></form></section>
    {/if}

    <section class="workbench-panel" style="margin-top: var(--space-xl)" aria-labelledby="fleet-title"><div class="workbench-panel__head"><h2 id="fleet-title">Registered workers</h2><div class="release-actions"><span class="timestamp">{workers.length} record{workers.length === 1 ? '' : 's'}</span><a class="button" href={includeArchived ? '/maintain/workers' : '/maintain/workers?archived=1'}>{includeArchived ? 'Hide archived' : 'Show archived'}</a></div></div>{#if workers.length}<div class="data-table-wrap"><table class="data-table data-table--workers"><thead><tr><th>Name</th><th>Software</th><th>Capabilities</th><th>Architecture</th><th>State</th><th>Leases</th><th>Last seen</th><th>Identity</th><th>Action</th></tr></thead><tbody>{#each workers as worker}<tr><td><strong>{worker.name}</strong><div class="timestamp">{worker.id}</div></td><td><span class="hash">{worker.daemon_version || 'Version not reported'}</span><div class="timestamp">{worker.runtime || 'Runtime not reported'}</div></td><td>{#if capabilities(worker.capabilities_json).length}<div class="worker-capabilities">{#each capabilities(worker.capabilities_json) as capability}<span class="tag">{capability}</span>{/each}</div>{:else}<span class="timestamp">None reported</span>{/if}</td><td>{worker.architecture}</td><td><StatusPill status={pillStatus(workerState(worker))} label={stateLabel(workerState(worker))} />{#if worker.paused_at}<div class="timestamp">paused {formatDate(worker.paused_at)}</div>{/if}{#if worker.removed_at}<div class="timestamp">archived {formatDate(worker.removed_at)}</div>{/if}</td><td>{activeLeases(worker)}</td><td>{formatDate(worker.last_seen_at)}</td><td><span class="hash">{worker.public_key.slice(0, 18)}…</span></td><td>{#if canManage}<div class="worker-actions">{#if workerState(worker) === 'active'}<form method="POST" action="?/pause"><input type="hidden" name="id" value={worker.id} /><button class="button" type="submit"><Icon name="clock" size={14} />Pause</button></form>{:else if workerState(worker) === 'draining' || workerState(worker) === 'paused'}<form method="POST" action="?/resume"><input type="hidden" name="id" value={worker.id} /><button class="button" type="submit"><Icon name="play" size={14} />Resume</button></form>{/if}{#if worker.status !== 'revoked'}<form method="POST" action="?/revoke"><input type="hidden" name="id" value={worker.id} /><button class="button" type="submit"><Icon name="lock" size={14} />Revoke</button></form>{:else if !worker.removed_at && activeLeases(worker) === 0}<form method="POST" action="?/archive"><input type="hidden" name="id" value={worker.id} /><button class="button" type="submit"><Icon name="archive" size={14} />Archive</button></form>{:else if worker.removed_at}<span class="timestamp">archived</span>{:else}<span class="timestamp">wait for leases</span>{/if}</div>{:else}<span class="timestamp">Read only</span>{/if}</td></tr>{/each}</tbody></table></div>{:else}<EmptyState title="No workers registered." description="Create a single-use enrollment token for a Linux host when a builder is ready to join the fleet." icon="server" />{/if}</section>

    <section class="section section--tight" style="padding-inline: 0" aria-labelledby="worker-rules-title"><div class="surface-grid"><article class="surface-panel"><div class="surface-panel__top"><h2 id="worker-rules-title">Lease rules</h2><Icon name="lock" size={20} /></div><p>Every claim is bound to worker identity, architecture, revision, manifest digest, and an expiring lease. Replays and stale completions fail closed.</p></article><article class="surface-panel surface-panel--recipe"><div class="surface-panel__top"><h2>Key boundary</h2><Icon name="shield" size={20} /></div><p>Signing happens in a separate service. Workers never receive package signing material, OAuth secrets, or broad Cloudflare credentials.</p></article></div></section>
  </section>
</MaintainerShell>
