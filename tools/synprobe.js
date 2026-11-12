// TCP-connect-only probe (no TLS): how often does the handshake itself fail, per target?
// Usage: node synprobe.js label=ip:port [label=ip:port ...]   (env N=attempts, CONC=parallel, TO=ms)
const net = require('net');
const N = Number(process.env.N) || 150;
const CONC = Number(process.env.CONC) || 10;
const TO = Number(process.env.TO) || 3500;

function attempt(ip, port) {
  return new Promise((res) => {
    const t0 = Date.now();
    let done = false;
    const s = net.connect({ host: ip, port });
    const fin = (v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { s.resetAndDestroy(); } catch (e) { try { s.destroy(); } catch (_) {} }
      res(v);
    };
    const timer = setTimeout(() => fin({ ok: false, why: 'SYN-timeout' }), TO);
    s.on('connect', () => fin({ ok: true, ms: Date.now() - t0 }));
    s.on('error', (e) => fin({ ok: false, why: e.code || e.message }));
  });
}

async function run(label, ip, port) {
  const results = [];
  let i = 0;
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (i < N) { i++; results.push(await attempt(ip, port)); }
  }));
  const ok = results.filter((r) => r.ok);
  const ms = ok.map((r) => r.ms).sort((a, b) => a - b);
  const why = {};
  results.filter((r) => !r.ok).forEach((r) => { why[r.why] = (why[r.why] || 0) + 1; });
  const slow = ms.filter((m) => m >= 900).length; // connected only after a SYN retransmit
  const q = (p) => (ms.length ? ms[Math.min(ms.length - 1, Math.floor(p * ms.length))] : '-');
  console.log(
    `${label.padEnd(22)} ${ip}:${port}`.padEnd(48) +
    ` ok=${ok.length}/${N} fail=${N - ok.length} ${JSON.stringify(why)}  connect ms p50=${q(0.5)} p95=${q(0.95)} max=${q(1)}  afterRetransmit=${slow}`
  );
}

(async () => {
  for (const a of process.argv.slice(2)) {
    const [label, rest] = a.split('=');
    const k = rest.lastIndexOf(':');
    await run(label, rest.slice(0, k), Number(rest.slice(k + 1)));
  }
})();
