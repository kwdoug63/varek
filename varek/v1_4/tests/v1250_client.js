// SPDX-License-Identifier: MIT
// v1250_client.js — run as the agent by test_v1250.sh (Node.js): dns.lookup
// goes through getaddrinfo, dns.resolve4 sends its own question (c-ares);
// both reach the Warden's stub for a name a wildcard rule allows.
//   node v1250_client.js <port> <wildcard-name> <outside-name>
const dns = require('dns'), http = require('http');
const [port, name, outside] = [+process.argv[2], process.argv[3], process.argv[4]];
function out(s, t0) { console.log(s + ' ' + (Date.now() - t0)); }
(async () => {
  let t0 = Date.now();
  await new Promise(r => dns.lookup(name, (e, a) => { out(e ? 'ERR resolve ' + e.code : 'OK resolve ' + a, t0); r(); }));
  t0 = Date.now();
  await new Promise(r => http.get({ host: name, port, timeout: 3000 }, res => { out('OK http ' + res.statusCode, t0); res.resume(); r(); })
    .on('error', e => { out('ERR http ' + e.code, t0); r(); }));
  t0 = Date.now();
  await new Promise(r => dns.lookup(outside, e => { out(e ? 'ERR unlisted ' + e.code : 'OK unlisted', t0); r(); }));
  t0 = Date.now();
  await new Promise(r => dns.resolve4(name, (e, a) => { out(e ? 'ERR resolve4 ' + e.code : 'OK resolve4 ' + a, t0); r(); }));
  t0 = Date.now();
  await new Promise(r => dns.resolve4(outside, e => { out(e ? 'ERR resolve4-unlisted ' + e.code : 'OK resolve4-unlisted', t0); r(); }));
})();
