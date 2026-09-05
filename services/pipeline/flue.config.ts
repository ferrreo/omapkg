import { defineConfig } from '@flue/runtime/config';

export default defineConfig({
  target: 'cloudflare',
  app: 'src/app.ts',
  cloudflare: 'src/cloudflare.ts',
  agents: 'factory-agent.ts',
  providers: ['openrouter'],
  tracing: false,
});
