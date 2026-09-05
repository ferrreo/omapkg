import { expect, test } from 'bun:test';
import { createModels } from '@earendil-works/pi-ai';
import { DEFAULT_MODEL, gatewayProvider } from '../services/pipeline/model';

const env = { AI_GATEWAY_ACCOUNT_ID: 'a'.repeat(32), AI_GATEWAY_ID: 'opr', AI_GATEWAY_TOKEN: 'gateway-test-token', AI_GATEWAY_BYOK_ALIAS: 'default' };

test('MiniMax M3 requests use Cloudflare OpenRouter BYOK without a provider authorization header', async () => {
  const models = createModels();
  models.setProvider(gatewayProvider(env));
  const model = models.getModel('openrouter', 'minimax/minimax-m3')!;
  expect(DEFAULT_MODEL).toBe('openrouter/minimax/minimax-m3');
  let called = false;
  const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    called = true;
    expect(String(input)).toBe(`https://gateway.ai.cloudflare.com/v1/${env.AI_GATEWAY_ACCOUNT_ID}/opr/openrouter/chat/completions`);
    const headers = new Headers(init?.headers);
    expect(headers.get('authorization')).toBeNull();
    expect(headers.get('cf-aig-authorization')).toBe('Bearer gateway-test-token');
    expect(headers.get('cf-aig-byok-alias')).toBe('default');
    expect(JSON.parse(String(init?.body)).model).toBe('minimax/minimax-m3');
    const chunks = [
      { id: 'test', choices: [{ index: 0, delta: { role: 'assistant', content: 'OK' }, finish_reason: null }] },
      { id: 'test', choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }
    ];
    return new Response(chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join('') + 'data: [DONE]\n\n', { headers: { 'Content-Type': 'text/event-stream' } });
  };
  const result = await models.completeSimple(model, { messages: [{ role: 'user', content: 'Say OK.', timestamp: 0 }] }, { fetch: fetch as typeof globalThis.fetch });
  expect(called).toBe(true);
  expect(result.stopReason).toBe('stop');
  expect(result.content).toContainEqual({ type: 'text', text: 'OK' });
});

test('missing gateway auth fails instead of using another provider', async () => {
  const models = createModels();
  models.setProvider(gatewayProvider({ ...env, AI_GATEWAY_TOKEN: undefined }));
  const result = await models.completeSimple(models.getModel('openrouter', 'minimax/minimax-m3')!, { messages: [] });
  expect(result.stopReason).toBe('error');
  expect(result.errorMessage).toContain('authentication is not configured');
});
