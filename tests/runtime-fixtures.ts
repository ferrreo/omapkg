export function runtimeEvidence(imageDigest: string) {
  return {
    buildEnvironment: { baseImage: `registry.example/builder@${imageDigest}`, preparedImage: `sha256:${'1'.repeat(64)}`, packages: ['glibc 2.43-1', 'make 4.4.1-1'] },
    runtimeEnvironment: { baseImage: `registry.example/runtime@sha256:${'2'.repeat(64)}`, preparedImage: `sha256:${'3'.repeat(64)}`, packages: ['glibc 2.43-1'] },
    runtimeAnalysis: { schemaVersion: 1, tool: 'namcap', toolVersion: '3.6.0', elf: [], findings: [], runtimeClosureComplete: false, unknowns: ['unexercised dynamic loading'] },
  };
}
