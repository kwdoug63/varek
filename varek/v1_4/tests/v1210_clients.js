// SPDX-License-Identifier: MIT
// Real Node.js clients for test_v1210.sh (run as the agent, under the Warden,
// and natively for the latency comparison). One mode per invocation:
//
//   http URL                 http.get; prints status and length
//   https URL CAFILE         https.get with that CA
//   tls IP PORT SNI PATH     tls.connect to an address, SNI and a verified
//                            certificate for SNI; HTTP/1.1 GET
//   net IP PORT              TCP echo
//   unix PATH                stream echo over a Unix socket
//   dgram IP PORT            connected UDP echo (twice)
//   bench-connect IP PORT N  net.connect N times; BENCH node-connect ... (us)
'use strict';
const fs = require('fs');
const [mode, ...a] = process.argv.slice(2);
const done = (s) => { console.log(s); };
const fail = (what, e) => { console.log(`CLIENT node ${what} ERROR ${e.code || e.message}`); process.exitCode = 1; };

function pct(v) {
  v.sort((x, y) => x - y);
  const n = v.length, q = (p) => v[Math.min(n - 1, Math.floor(n * p))].toFixed(0);
  return `n=${n} p50=${q(0.5)} p90=${q(0.9)} p99=${q(0.99)} max=${v[n - 1].toFixed(0)} ` +
         `mean=${(v.reduce((s, x) => s + x, 0) / n).toFixed(0)} (us)`;
}

if (mode === 'http' || mode === 'https') {
  const mod = require(mode);
  const opts = mode === 'https' ? { ca: fs.readFileSync(a[1]) } : {};
  mod.get(a[0], opts, (r) => {
    let n = 0;
    r.on('data', (d) => { n += d.length; });
    r.on('end', () => done(`CLIENT node-${mode} ${a[0]} status=${r.statusCode} bytes=${n}`));
  }).on('error', (e) => fail(mode, e));
} else if (mode === 'tls') {
  const tls = require('tls');
  const s = tls.connect({ host: a[0], port: +a[1], servername: a[2] }, () => {
    s.write(`GET ${a[3]} HTTP/1.1\r\nHost: ${a[2]}\r\nConnection: close\r\nUser-Agent: varek-test\r\n\r\n`);
  });
  let got = '';
  s.on('data', (d) => { got += d.toString('latin1'); });
  s.on('end', () => done(`CLIENT node-tls ${a[2]}@${a[0]} ${got.split('\r\n')[0]} authorized=${s.authorized}`));
  s.on('error', (e) => fail('tls', e));
} else if (mode === 'net' || mode === 'unix') {
  const net = require('net');
  const s = mode === 'net' ? net.connect(+a[1], a[0]) : net.connect(a[0]);
  s.on('connect', () => s.write('ping'));
  s.on('data', (d) => { done(`CLIENT node-${mode} ${a.join(':')} echo=${d}`); s.end(); });
  s.on('error', (e) => fail(mode, e));
} else if (mode === 'dgram') {
  const s = require('dgram').createSocket('udp4');
  const got = [];
  s.on('message', (m) => {
    got.push(m.toString());
    if (got.length === 2) { done(`CLIENT node-dgram ${a[0]}:${a[1]} echo=${got.join(',')}`); s.close(); }
  });
  s.on('error', (e) => fail('dgram', e));
  s.connect(+a[1], a[0], () => { s.send('one'); s.send('two'); });
  setTimeout(() => { if (got.length < 2) { fail('dgram', { message: 'timeout' }); s.close(); } }, 5000).unref();
} else if (mode === 'bench-connect') {
  const net = require('net');
  const n = +a[2], t = [];
  const one = () => {
    const t0 = process.hrtime.bigint();
    const s = net.connect(+a[1], a[0]);
    s.on('connect', () => {
      t.push(Number(process.hrtime.bigint() - t0) / 1000);
      s.destroy();
      if (t.length < n) setImmediate(one); else done(`BENCH node-connect ${pct(t)}`);
    });
    s.on('error', (e) => fail('bench', e));
  };
  one();
} else {
  console.log(`unknown mode ${mode}`);
  process.exitCode = 2;
}
