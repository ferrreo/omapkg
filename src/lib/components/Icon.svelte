<script module lang="ts">
  export type IconName =
    | 'activity'
    | 'archive'
    | 'arrow'
    | 'book'
    | 'box'
    | 'check'
    | 'chevron'
    | 'clock'
    | 'code'
    | 'download'
    | 'eye'
    | 'external'
    | 'file'
    | 'git'
    | 'lock'
    | 'log'
    | 'menu'
    | 'package'
    | 'play'
    | 'plus'
    | 'refresh'
    | 'search'
    | 'server'
    | 'shield'
    | 'terminal'
    | 'upload'
    | 'user'
    | 'x';
</script>

<script lang="ts">
  import type { IconName as IconNameType } from './Icon.svelte';

  export let name: IconNameType = 'activity';
  export let size = 16;
  export let strokeWidth = 1.7;

  const icons: Record<IconNameType, string[]> = {
    activity: ['M3 12h4l2-7 4 14 2-7h6'],
    archive: ['M4 7h16v13H4z', 'M3 4h18v3H3z', 'M9 12h6'],
    arrow: ['M5 12h13', 'm13 6 6 6-6 6'],
    book: ['M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 0-3 3z', 'M5 4v16a3 3 0 0 1 3-3h11'],
    box: ['m4 7 8-4 8 4-8 4z', 'M4 7v10l8 4 8-4V7', 'M12 11v10'],
    check: ['m5 12 4 4L19 6'],
    chevron: ['m7 9 5 5 5-5'],
    clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M12 7v5l3 2'],
    code: ['m8 9-4 3 4 3', 'm16 9 4 3-4 3', 'm14 5-4 14'],
    download: ['M12 3v12', 'm7 10 5 5 5-5', 'M4 20h16'],
    eye: ['M3 12s3-5 9-5 9 5 9 5-3 5-9 5-9-5-9-5Z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z'],
    external: ['M14 4h6v6', 'm20 4-9 9', 'M18 13v6H5V6h6'],
    file: ['M6 3h8l4 4v14H6z', 'M14 3v5h5'],
    git: ['M12 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z', 'M6 9v5a3 3 0 0 0 3 3h6a3 3 0 0 0 3-3V9', 'M12 9v11'],
    lock: ['M6 10h12v10H6z', 'M8 10V7a4 4 0 0 1 8 0v3'],
    log: ['M5 4h14v16H5z', 'M8 8h8', 'M8 12h8', 'M8 16h5'],
    menu: ['M4 7h16', 'M4 12h16', 'M4 17h16'],
    package: ['M4 7 12 3l8 4-8 4z', 'M4 7v10l8 4 8-4V7', 'M12 11v10'],
    play: ['m8 5 11 7-11 7z'],
    plus: ['M12 5v14', 'M5 12h14'],
    refresh: ['M20 11a8 8 0 0 0-14-4L4 9', 'M4 4v5h5', 'M4 13a8 8 0 0 0 14 4l2-2', 'M20 20v-5h-5'],
    search: ['m20 20-4.5-4.5', 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13Z'],
    server: ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M7 7h.01', 'M7 17h.01'],
    shield: ['M12 3 19 6v5c0 5-3 8-7 10-4-2-7-5-7-10V6z', 'm9 12 2 2 4-4'],
    terminal: ['M4 5h16v14H4z', 'm7 9 3 3-3 3', 'M13 15h4'],
    upload: ['M12 15V3', 'm7 8 5-5 5 5', 'M4 20h16'],
    user: ['M20 21a8 8 0 0 0-16 0', 'M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z'],
    x: ['m6 6 12 12', 'm18 6-12 12']
  };

  $: paths = icons[name] ?? icons.activity;
</script>

<svg
  aria-hidden="true"
  fill="none"
  height={size}
  viewBox="0 0 24 24"
  width={size}
  xmlns="http://www.w3.org/2000/svg"
>
  {#each paths as d}
    <path d={d} stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width={strokeWidth} />
  {/each}
</svg>
