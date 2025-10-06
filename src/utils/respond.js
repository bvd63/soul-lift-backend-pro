export function ok(data = {}) {
  // backward compatible shape: { ok: true, ...data }
  return Object.assign({ ok: true }, data);
}

export function error(message = 'error', code = 'error', details = {}) {
  return { ok: false, error: { message, code, details } };
}

export function sendOk(reply, data = {}) { reply.code(200).send(ok(data)); }
export function sendError(reply, message = 'error', code = 'error', status = 400, details = {}) { reply.code(status).send(error(message, code, details)); }
