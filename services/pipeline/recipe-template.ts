import { shellQuote } from './security';
import {
  TYPED_TEMPLATE_DEFINITIONS,
  TYPED_TEMPLATE_IDS,
  typedTemplateCommands,
  typedTemplateOutputCommands,
  typedTemplateOutputs,
  validateTypedTemplate,
  type TypedRecipeTemplate,
} from './typed-templates';

export {
  TYPED_TEMPLATE_DEFINITIONS,
  TYPED_TEMPLATE_IDS,
  TEMPLATE_FAMILY_MATRIX,
  typedTemplateCommands,
  typedTemplateOutputCommands,
  typedTemplateOutputs,
  typedTemplateSchema,
  validateTypedTemplate,
} from './typed-templates';

export type { TypedRecipeTemplate, TypedTemplateId, PinnedTemplateInput, TemplateOutputSpec, TemplateRuntimeProbe } from './typed-templates';

export type RecipeTemplate = { id: 'make-v1' | 'go-v1'; binary: string; target?: string } | TypedRecipeTemplate;

// Versioned templates are immutable. Change the ID when execution changes.
const LEGACY_TEMPLATE_DEFINITIONS = {
  'make-v1': { build: ['./configure --prefix=/usr', 'make'], package: ['make DESTDIR="$pkgdir" install'], smoke: ["'/usr/bin/BINARY' --version"] },
  'go-v1': { build: ['GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=off go build -trimpath -mod=vendor -o opr-binary TARGET'], package: ['install -Dm755 opr-binary "$pkgdir/usr/bin/BINARY"'], smoke: ["'/usr/bin/BINARY' --version"] },
} as const;

export const TEMPLATE_DEFINITIONS = {
  ...LEGACY_TEMPLATE_DEFINITIONS,
  ...TYPED_TEMPLATE_DEFINITIONS,
} as const;

function isTypedTemplate(value: RecipeTemplate): value is TypedRecipeTemplate {
  return Boolean(value && typeof value === 'object' && typeof value.id === 'string' && (TYPED_TEMPLATE_IDS as readonly string[]).includes(value.id));
}

export function isVerifiedArtifactTemplate(value: unknown): boolean {
  const candidate = value as RecipeTemplate;

  return isTypedTemplate(candidate) && ['deb-v1', 'rpm-v1', 'appimage-v1', 'run-v1'].includes(candidate.id);
}

export function templateCommands(value: RecipeTemplate): { build: string[]; package: string[]; smoke: string[] } {
  if (isTypedTemplate(value)) {
    validateTypedTemplate(value);

    return typedTemplateCommands(value);
  }

  const legacy = value as Extract<RecipeTemplate, { id: 'make-v1' | 'go-v1' }>;

  if (!legacy || !Object.hasOwn(LEGACY_TEMPLATE_DEFINITIONS, legacy.id) ||
      Object.keys(legacy).some((key) => !['id', 'binary', 'target'].includes(key)) ||
      typeof legacy.binary !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/.test(legacy.binary)) {
    throw new Error('Invalid recipe template or executable name');
  }

  const smoke = LEGACY_TEMPLATE_DEFINITIONS[legacy.id].smoke.map((command) => command.replace('BINARY', legacy.binary));

  if (legacy.id === 'make-v1') {
    if (legacy.target !== undefined) throw new Error('make-v1 does not accept build arguments');

    return { build: [...LEGACY_TEMPLATE_DEFINITIONS['make-v1'].build], package: [...LEGACY_TEMPLATE_DEFINITIONS['make-v1'].package], smoke };
  }

  const target = legacy.target ?? '.';

  if (typeof target !== 'string' || (target !== '.' && (!/^\.\/[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$/.test(target) || target.split('/').slice(1).some((part) => !part || part === '.' || part === '..')))) {
    throw new Error('go-v1 target must be a relative package directory');
  }

  return {
    build: LEGACY_TEMPLATE_DEFINITIONS['go-v1'].build.map((command) => command.replace('TARGET', shellQuote(target))),
    package: LEGACY_TEMPLATE_DEFINITIONS['go-v1'].package.map((command) => command.replace('BINARY', legacy.binary)), smoke,
  };
}
