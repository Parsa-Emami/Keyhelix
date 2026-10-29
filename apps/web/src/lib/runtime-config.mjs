const allowed = new Set(['projectId', 'apiBasePath', 'engineEnabled', 'maxPreviewBytes']);

export function validateRuntimeConfig(value, expectedProjectId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Configuration must be an object.');
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error('Unknown public configuration field.');
  if (!/^[a-z][a-z0-9-]{1,63}$/.test(value.projectId) || value.projectId !== expectedProjectId) throw new Error('Project configuration mismatch.');
  if (value.apiBasePath !== '/api') throw new Error('Only the same-origin /api path is supported.');
  // The public configuration never advertises an engine: domain capability is
  // discovered from engine readiness and the authenticated session instead.
  if (value.engineEnabled !== false) throw new Error('Engine integration must be explicitly disabled in public configuration.');
  if (!Number.isSafeInteger(value.maxPreviewBytes) || value.maxPreviewBytes < 1 || value.maxPreviewBytes > 1048576) throw new Error('Preview limit must be 1 to 1048576 bytes.');
  return Object.freeze({ ...value });
}

export function validateHealth(value) {
  if (!value || value.status !== 'ok' || value.scope !== 'engine-runtime' || typeof value.coreReady !== 'boolean' ||
      !/^\d+\.\d+\.\d+$/.test(value.version) || !/^go\d+\.\d+\.\d+$/.test(value.toolchain) ||
      Object.keys(value).sort().join(',') !== 'coreReady,scope,status,toolchain,version') throw new Error('Invalid engine health response.');
  return value;
}
