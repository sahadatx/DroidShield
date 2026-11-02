/* Trusted fixed observation program. Never reads arguments, return values or memory. */
'use strict';
const counters = {filesystem_open: 0, socket_connect: 0, dns_lookup: 0};
const hooked = new Set();
const listeners = [];
for (const [name, category] of [
  ['open', 'filesystem_open'], ['openat', 'filesystem_open'],
  ['connect', 'socket_connect'], ['getaddrinfo', 'dns_lookup']
]) {
  try {
    const address = Module.getGlobalExportByName(name);
    listeners.push(Interceptor.attach(address, {onEnter() {
      counters[category] = Math.min(counters[category] + 1, 1000000);
    }}));
    hooked.add(category);
  } catch (_) { /* Missing symbols reduce declared hook coverage; never emit raw errors. */ }
}
rpc.exports = {
  summary() {
    return {version: Frida.version, hooked_apis: Array.from(hooked).sort(), counters};
  }
};
