export function ok(data = {}) {
  return { ok: true, ...data };
}

export function error(message, code = 'error', details = {}) {
  return { error: message, code, ...details };
}
