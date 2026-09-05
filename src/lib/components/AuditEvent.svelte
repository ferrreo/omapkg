<script lang="ts">
  import type { AuditEvent } from '../model';

  export let event: AuditEvent;
  export let actorNames: Record<string, string> = {};

  type LabelledEvent = AuditEvent & { actor_name?: string | null; actor_login?: string | null; target_name?: string | null };
  $: labelled = event as LabelledEvent;
  $: actorLabel = actorNames[event.actor] || labelled.actor_name || labelled.actor_login || (event.actor.startsWith('github:') ? 'GitHub user' : event.actor.startsWith('user:') ? 'Signed-in user' : event.actor);
  $: targetLabel = labelled.target_name || actorNames[event.target] || event.target;

  $: date = event.created_at ? new Date(event.created_at * 1000).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z') : '—';
</script>

<article class="audit-event">
  <span class="timestamp">{date}</span>
  <span class="audit-event__action">{event.action}</span>
  <span class="audit-event__actor"><span>{actorLabel}</span> <span aria-hidden="true">→</span> <span>{targetLabel}</span></span>
  <span class="audit-event__detail">{event.detail || 'No detail recorded.'}</span>
</article>
