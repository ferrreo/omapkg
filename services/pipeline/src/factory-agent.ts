'use agent';

import { PackageFactory as RootPackageFactory } from '../../../src/lib/server/factory';
import { PreservedRepairFactory as RootPreservedRepairFactory } from '../../../src/lib/server/preserved-factory';

export function PackageFactory(...args: Parameters<typeof RootPackageFactory>) {
  return RootPackageFactory(...args);
}

Object.assign(PackageFactory, RootPackageFactory);

export function PreservedRepairFactory(...args: Parameters<typeof RootPreservedRepairFactory>) {
  return RootPreservedRepairFactory(...args);
}

Object.assign(PreservedRepairFactory, RootPreservedRepairFactory);
