<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import PublicNav from '$lib/components/PublicNav.svelte';
  import { CRASH_CONSENT_VERSION, CRASH_REPORT_RETENTION_DAYS } from '$lib/reports';

  export let data: { user?: { id: string; name?: string; image?: string | null } | null; role?: string };

  $: user = data?.user || null;
  $: role = data?.role || 'public';
</script>

<svelte:head><title>Privacy · omapkg</title><meta name="description" content="Privacy policy for omapkg feedback and opt-in crash reports." /></svelte:head>

<PublicNav {user} {role} />

<main class="public-main">
  <article class="section site-width--narrow" aria-labelledby="privacy-title">
    <div class="section__head"><div><span class="eyebrow">Privacy policy · {CRASH_CONSENT_VERSION}</span><h1 id="privacy-title">Reports by choice</h1></div><p>omapkg does not collect automatic usage telemetry. A crash report is sent only when you complete the opt-in form.</p></div>

    <div class="detail-stack">
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>What a crash report contains</h2><Icon name="file" size={18} /></div><p class="prose">The submission contains the release ID, the crash summary you enter, a consent flag, and consent version <code>{CRASH_CONSENT_VERSION}</code>. It is recorded without a name, account ID, or IP address. It does not include device inventory, file paths, environment variables, or background telemetry.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>What to leave out</h2><Icon name="lock" size={18} /></div><p class="prose">Do not include personal details, home paths, access tokens, private URLs, or complete log files in a summary. Describe the release, action, and visible failure in your own words.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Temporary rate limiting</h2><Icon name="clock" size={18} /></div><p class="prose">To limit abuse, omapkg may keep a daily rotating digest derived from your IP address for up to 48 hours. It is used only for the submission limit, then deleted. It is not stored with the crash report.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Retention and review</h2><Icon name="activity" size={18} /></div><p class="prose">Raw crash report text is removed after {CRASH_REPORT_RETENTION_DAYS} days. Maintainers review reports scoped to a published release. Confirmed incident metadata and audit entries remain so release decisions keep their context.</p></section>
      <section class="workbench-panel"><div class="workbench-panel__head"><h2>Operational logs</h2><Icon name="server" size={18} /></div><p class="prose">Cloudflare operational connection logs are separate from omapkg crash report fields and follow Cloudflare's operational policies.</p></section>
      <section class="workbench-panel surface-panel--recipe"><div class="workbench-panel__head"><h2>Feedback is separate</h2><Icon name="user" size={18} /></div><p class="prose">Signed-in release feedback is attached to your account and the release. It is separate from anonymous crash reporting; the crash form does not use your GitHub identity.</p></section>
    </div>
  </article>

  <footer class="site-footer"><p>omapkg · {CRASH_CONSENT_VERSION}</p><nav class="site-footer__links" aria-label="Footer navigation"><a href="/docs">Docs</a><a href="/packages">Packages</a><a href="/request">Request</a></nav></footer>
</main>
