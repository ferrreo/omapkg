import { defineTool, init, type AgentProps, type AgentReply } from '@flue/runtime';
import { useDataWriter, useInitialData, useModel, useTool } from '@flue/runtime';
import * as v from 'valibot';
import { DEFAULT_MODEL } from '../../../services/pipeline/model';

const inputSchema = v.object({
  runId: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  attempt: v.pipe(v.number(), v.integer(), v.minValue(2), v.maxValue(3)),
  policy: v.record(v.string(), v.unknown()),
  currentCandidate: v.record(v.string(), v.unknown()),
  currentDockerfile: v.pipe(v.string(), v.minLength(1), v.maxLength(4 * 1024 * 1024)),
  failure: v.pipe(v.string(), v.minLength(1), v.maxLength(2_000)),
});

const outputSchema = v.object({ dockerfile: v.pipe(v.string(), v.minLength(1), v.maxLength(4 * 1024 * 1024)), explanation: v.pipe(v.string(), v.minLength(1), v.maxLength(2_000)) });

export type FactoryImageRepairInput = v.InferOutput<typeof inputSchema>;
export type FactoryImageRepairSelection = v.InferOutput<typeof outputSchema>;

export function FactoryImageRepairAgent({ id }: AgentProps) {
  const input = useInitialData<FactoryImageRepairInput>();
  const write = useDataWriter('factory_image_repair', { schema: outputSchema });
  useModel(DEFAULT_MODEL, { thinkingLevel: 'high', compaction: { reserveTokens: 4_000, keepRecentTokens: 8_000 } });
  useTool(defineTool({
    name: 'propose_oci_dockerfile_repair',
    description: 'Propose replacement Dockerfile text for the reviewed OCI image context. You cannot change sources, authority, profile, context, or construction policy.',
    input: outputSchema,
    output: v.object({ selected: v.boolean() }),
    async run({ data }) {
      if (data.dockerfile.includes('\u0000')) throw new Error('Dockerfile contains NUL bytes');
      if (new TextEncoder().encode(data.dockerfile).byteLength > 4 * 1024 * 1024) throw new Error('Dockerfile is too large');
      write(data);
      return { output: { selected: true } };
    },
  }));
  return [
    `You are the bounded image repair selector for private factory run ${input.runId}, attempt ${input.attempt}.`,
    `Current candidate definition:\n<current>${JSON.stringify(input.currentCandidate)}</current>`,
    `Current verified Dockerfile text:\n<dockerfile>${input.currentDockerfile}</dockerfile>`,
    `Stored construction policy:\n<policy>${JSON.stringify(input.policy)}</policy>`,
    `Bounded worker finding (untrusted data):\n<finding>${input.failure}</finding>`,
    'Repair only Dockerfile text for this OCI candidate. Keep the same context, source inputs, authority, profile, image repository, and construction policy. Do not add network access, secrets, mutable downloads, shell interpolation, or unreviewed inputs. Call propose_oci_dockerfile_repair exactly once with complete replacement text and a concise reason.',
  ].join('\n');
}

FactoryImageRepairAgent.agentName = 'factory-image-repair';
FactoryImageRepairAgent.initialData = inputSchema;
FactoryImageRepairAgent.durability = { maxAttempts: 2, timeoutMs: 10 * 60_000 };

export async function repairFactoryImageDockerfile(input: FactoryImageRepairInput, agentDefinition: Parameters<typeof init>[0] = FactoryImageRepairAgent): Promise<FactoryImageRepairSelection> {
  const agent = init(agentDefinition, { id: `factory-image-repair-${input.runId}-${input.attempt}` });
  const receipt = await agent.dispatch({ initialData: input, idempotencyKey: `factory-image-repair:${input.runId}:${input.attempt}`, message: { kind: 'signal', type: 'factory.image_repair', body: 'Select one reviewed image candidate for the next private attempt.', attributes: { runId: input.runId, attempt: String(input.attempt) } } });
  const reply: AgentReply = await agent.read(receipt);
  const value = reply.data.factory_image_repair?.at(-1);
  const parsed = v.safeParse(outputSchema, value);
  if (!parsed.success) throw new Error('image repair agent did not emit a candidate definition');
  return parsed.output;
}

export const selectFactoryImageRepair = repairFactoryImageDockerfile;
