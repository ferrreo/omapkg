import { error } from '@sveltejs/kit';
import type { Architecture } from '$lib/model';
import { distributionReleaseWorkbench } from '$lib/server/release-workbench';
import { environment } from '$lib/server/http';
import type { PageServerLoad } from './$types';

function requestedArchitecture(value: string | null): Architecture | null {
  if (value === null || value === '') return null;
  if (value !== 'x86_64' && value !== 'aarch64') error(400, 'Architecture must be x86_64 or aarch64.');
  return value;
}

export const load: PageServerLoad = async (event) => {
  const env = environment(event);
  const architecture = requestedArchitecture(event.url.searchParams.get('architecture'));
  const systemVersion = event.url.searchParams.get('systemVersion')?.trim() || null;
  if (systemVersion && !/^(?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5})(?:-(?:rc|edge\.)\d{1,5})?$/.test(systemVersion)) {
    error(400, 'System version must use an Omarchy version such as 4.0.3 or 4.0.3-rc2.');
  }
  const view = await distributionReleaseWorkbench(env, systemVersion, architecture);
  return { view, architecture: architecture ?? '', systemVersion: systemVersion ?? '' };
};
