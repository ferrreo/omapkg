'use agent';

import { PackageFactory as RootPackageFactory } from '../../../src/lib/server/factory';

export function PackageFactory(...args: Parameters<typeof RootPackageFactory>) {
  return RootPackageFactory(...args);
}

Object.assign(PackageFactory, RootPackageFactory);
