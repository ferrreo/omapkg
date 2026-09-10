export function shellCheckCommand(recipe: string, smoke: string[], publicRecipe?: string | null): string {
  const files = [
    { name: 'PKGBUILD', shell: 'bash', text: recipe },
    { name: 'smoke.sh', shell: 'sh', text: `set -eu\n${smoke.join('\n')}\n` },
    ...(publicRecipe ? [{ name: 'public.PKGBUILD', shell: 'bash', text: publicRecipe }] : []),
  ];

  return [
    'set -eu',
    'checkdir="$(mktemp -d /tmp/opr-shellcheck.XXXXXXXX)"',
    'trap \'rm -rf "$checkdir"\' EXIT',
    ...files.flatMap((file) => {
      let binary = '';

      for (const byte of new TextEncoder().encode(file.text)) binary += String.fromCharCode(byte);

      return [
        `printf '%s' '${btoa(binary)}' | base64 --decode > "$checkdir/${file.name}"`,
        `${file.shell === 'sh' ? '/bin/sh' : '/bin/bash --noprofile --norc'} -n "$checkdir/${file.name}"`,
        `/usr/bin/shellcheck --norc --shell=${file.shell} --severity=error "$checkdir/${file.name}"`,
      ];
    }),
    '/usr/bin/shellcheck --version',
  ].join('\n');
}
