// SPDX-License-Identifier: MIT
// v1240_client.js — run as the agent by test_v1240.sh (Node.js: dns.lookup
// goes through getaddrinfo; dns.resolve4 queries DNS itself and must fail).
const dns = require('dns'), http = require('http');
const port = +process.argv[2];
const t = () => Date.now();
function out(s, t0) { console.log(s + ' ' + (Date.now() - t0)); }
(async () => {
  let t0 = t();
  await new Promise(r => dns.lookup('api.example.com', (e, a) => { out(e ? 'ERR resolve ' + e.code : 'OK resolve ' + a, t0); r(); }));
  t0 = t();
  await new Promise(r => http.get({ host: 'api.example.com', port, timeout: 3000 }, res => { out('OK http ' + res.statusCode, t0); res.resume(); r(); })
    .on('error', e => { out('ERR http ' + e.code, t0); r(); }));
  t0 = t();
  await new Promise(r => dns.lookup('other.example.com', e => { out(e ? 'ERR unlisted ' + e.code : 'OK unlisted', t0); r(); }));
  t0 = t();
  await new Promise(r => dns.resolve4('api.example.com', (e, a) => { out(e ? 'ERR resolve4 ' + e.code : 'OK resolve4 ' + a, t0); r(); }));
})();
