import { createProvider } from '@earendil-works/pi-ai';
import { openAICompletionsApi } from '@earendil-works/pi-ai/api/openai-completions.lazy';
import { openrouterProvider } from '@earendil-works/pi-ai/providers/openrouter';

// OpenRouter's canonical ID for MiniMax M3.
export const DEFAULT_MODEL = 'openrouter/minimax/minimax-m3';
export interface GatewayEnv {
  AI_GATEWAY_ACCOUNT_ID: string;
  AI_GATEWAY_ID: string;
  AI_GATEWAY_BYOK_ALIAS?: string;
  AI_GATEWAY_TOKEN?: string;
}

export function gatewayProvider(env: GatewayEnv) {
  if (!/^[a-f0-9]{32}$/.test(env.AI_GATEWAY_ACCOUNT_ID) || !/^[a-zA-Z0-9_-]{1,64}$/.test(env.AI_GATEWAY_ID)) {
    throw new Error('Cloudflare AI Gateway account and gateway IDs are required.');
  }
  const baseUrl = `https://gateway.ai.cloudflare.com/v1/${env.AI_GATEWAY_ACCOUNT_ID}/${env.AI_GATEWAY_ID}/openrouter`;
  const model = openrouterProvider().getModels().find((model) => model.id === 'minimax/minimax-m3');
  if (!model) throw new Error('MiniMax M3 is missing from the installed model catalog.');
  return createProvider({
    id: 'openrouter',
    name: 'OpenRouter through Cloudflare AI Gateway',
    models: [{ ...model, baseUrl }],
    auth: { apiKey: {
      name: 'Cloudflare AI Gateway BYOK',
      resolve: async () => {
        if (!env.AI_GATEWAY_TOKEN) throw new Error('Cloudflare AI Gateway authentication is not configured.');
        return { auth: { baseUrl, headers: {
          authorization: null,
          'cf-aig-authorization': `Bearer ${env.AI_GATEWAY_TOKEN}`,
          'cf-aig-byok-alias': env.AI_GATEWAY_BYOK_ALIAS ?? 'default'
        } } };
      }
    } },
    api: openAICompletionsApi()
  });
}
