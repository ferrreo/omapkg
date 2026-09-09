import { shellQuote } from './security';

export type RecipeTemplate = { id: 'make-v1' | 'go-v1'; binary: string; target?: string };

// Versioned templates are immutable. Change the ID when execution changes.
export const TEMPLATE_DEFINITIONS = {
  'make-v1': { build: ['./configure --prefix=/usr', 'make'], package: ['make DESTDIR="$pkgdir" install'], smoke: ["'/usr/bin/BINARY' --version"] },
  'go-v1': { build: ['GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=off go build -trimpath -mod=vendor -o opr-binary TARGET'], package: ['install -Dm755 opr-binary "$pkgdir/usr/bin/BINARY"'], smoke: ["'/usr/bin/BINARY' --version"] },
} as const;

export function templateCommands(value: RecipeTemplate): { build: string[]; package: string[]; smoke: string[] } {
  if (!value || !Object.hasOwn(TEMPLATE_DEFINITIONS, value.id) ||
      Object.keys(value).some((key) => !['id', 'binary', 'target'].includes(key)) ||
      typeof value.binary !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/.test(value.binary)) {
    throw new Error('Invalid recipe template or executable name');
  }
  const smoke = TEMPLATE_DEFINITIONS[value.id].smoke.map((command) => command.replace('BINARY', value.binary));
  if (value.id === 'make-v1') {
    if (value.target !== undefined) throw new Error('make-v1 does not accept build arguments');
    return { build: [...TEMPLATE_DEFINITIONS['make-v1'].build], package: [...TEMPLATE_DEFINITIONS['make-v1'].package], smoke };
  }
  const target = value.target ?? '.';
  if (typeof target !== 'string' || (target !== '.' && (!/^\.\/[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$/.test(target) || target.split('/').slice(1).some((part) => !part || part === '.' || part === '..')))) {
    throw new Error('go-v1 target must be a relative package directory');
  }
  return {
    build: TEMPLATE_DEFINITIONS['go-v1'].build.map((command) => command.replace('TARGET', shellQuote(target))),
    package: TEMPLATE_DEFINITIONS['go-v1'].package.map((command) => command.replace('BINARY', value.binary)), smoke,
  };
}
