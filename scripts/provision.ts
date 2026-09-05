type Json = Record<string, any>;

const readDotEnv = async () => {
  const file = Bun.file('.env');
  if (!(await file.exists())) return {} as Record<string, string>;
  const values: Record<string, string> = {};
  for (const raw of (await file.text()).split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    const value = match[2].trim();
    values[match[1]] = value.replace(/^(['"])(.*)\1$/, '$2');
  }
  return values;
};

const fileEnv = await readDotEnv();
const env = { ...fileEnv, ...process.env };
const accountId = env.CLOUDFLARE_ACCOUNT_ID;
const token = env.CLOUDFLARE_API_TOKEN ?? env.CLOUDFLARE_TOKEN_CREATION_TOKEN;
if (!accountId || !token) throw new Error('CLOUDFLARE_ACCOUNT_ID and a Cloudflare API token are required.');
const databaseName = env.D1_DATABASE_NAME ?? 'omapkg';
const bucketName = env.ARTIFACTS_BUCKET_NAME ?? 'omapkg-artifacts';
const gatewayId = env.AI_GATEWAY_ID ?? 'default';

const api = async (path: string, init: RequestInit = {}) => {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) }
  });
  const body = await response.json() as Json;
  if (!response.ok || body.success !== true) {
    const message = (body.errors ?? []).map((error: Json) => error.message).join('; ') || response.statusText;
    throw new Error(`${path}: ${message}`);
  }
  return body.result as any;
};

const d1 = await api(`/accounts/${accountId}/d1/database`) as Json[];
const database = d1.find((item) => item.name === databaseName) ?? await api(`/accounts/${accountId}/d1/database`, {
  method: 'POST', body: JSON.stringify({ name: databaseName, jurisdiction: 'eu', read_replication: { mode: 'disabled' } })
});

const r2Result = await api(`/accounts/${accountId}/r2/buckets`, { headers: { 'cf-r2-jurisdiction': 'eu' } }) as Json | Json[];
const buckets = Array.isArray(r2Result) ? r2Result : r2Result.buckets ?? [];
const bucket = buckets.find((item: Json) => item.name === bucketName) ?? await api(`/accounts/${accountId}/r2/buckets`, {
  method: 'POST', headers: { 'cf-r2-jurisdiction': 'eu' }, body: JSON.stringify({ name: bucketName, locationHint: env.R2_LOCATION_HINT ?? 'weur' })
});

const gateways = await api(`/accounts/${accountId}/ai-gateway/gateways`) as Json[];
const gateway = gateways.find((item) => item.id === gatewayId) ?? await api(`/accounts/${accountId}/ai-gateway/gateways`, {
  method: 'POST', body: JSON.stringify({
    id: gatewayId, cache_invalidate_on_update: true, cache_ttl: 0, collect_logs: true,
    rate_limiting_interval: 0, rate_limiting_limit: 0, authentication: true, workers_ai_billing_mode: 'postpaid'
  })
});

const subdomain = (await api(`/accounts/${accountId}/workers/subdomain`)).subdomain;
let customDomain: string | undefined;
if (env.PUBLIC_ORIGIN?.trim()) {
  const origin = new URL(env.PUBLIC_ORIGIN.trim());
  if (origin.protocol === 'https:' && origin.hostname) customDomain = origin.origin;
}
console.log(JSON.stringify({
  account_id: accountId,
  workers_dev_origin: `https://${env.WEB_WORKER_NAME ?? 'omapkg'}.${subdomain}.workers.dev`,
  d1: { name: database.name, id: database.uuid },
  r2: { name: bucket.name, location: bucket.location, jurisdiction: bucket.jurisdiction },
  ai_gateway: { id: gateway.id },
  ...(customDomain ? { custom_domain: customDomain } : {})
}, null, 2));
