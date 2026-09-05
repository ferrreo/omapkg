# Model routing

The factory uses MiniMax M3 through OpenRouter and Cloudflare AI Gateway. OpenRouter's canonical model ID is `minimax/minimax-m3`; Flue uses `openrouter/minimax/minimax-m3`. Source-review subagents inherit that model.

Requests follow this route:

```text
Flue -> Cloudflare AI Gateway (omapkg) -> OpenRouter -> MiniMax M3
```

The OpenRouter key stays in Cloudflare BYOK under alias `default`. The pipeline sends its scoped `AI_GATEWAY_TOKEN` in `cf-aig-authorization` and selects the alias with `cf-aig-byok-alias`. It does not send an OpenRouter `Authorization` header. Missing gateway credentials fail the request; there is no direct-provider fallback.

Pipeline configuration:

| Setting | Value |
| --- | --- |
| `AI_GATEWAY_ACCOUNT_ID` | Cloudflare account identifier from the deployment secret store |
| `AI_GATEWAY_ID` | `omapkg` |
| `AI_GATEWAY_BYOK_ALIAS` | `default` |
| `AI_GATEWAY_TOKEN` | Pipeline-only Worker secret with AI Gateway Run permission |

The gateway token must not be passed to source sandboxes or Linux build workers. Provider setup lives in `services/pipeline/model.ts`; the factory selects its shared `DEFAULT_MODEL` constant.

## Verification

`bun test tests/model.test.ts` checks the actual SDK request URL, model ID, gateway headers, absence of provider credentials, and failure when gateway authentication is missing.

A live streaming request through this provider returned `OK` during acceptance. This verifies model routing; package-generation acceptance remains a separate check.

References: [Cloudflare OpenRouter endpoint](https://developers.cloudflare.com/ai-gateway/usage/providers/openrouter/), [Cloudflare BYOK](https://developers.cloudflare.com/ai-gateway/configuration/bring-your-own-keys/), [MiniMax M3 on OpenRouter](https://openrouter.ai/minimax/minimax-m3/providers), [Flue provider API](https://flueframework.com/docs/reference/provider-api/).
