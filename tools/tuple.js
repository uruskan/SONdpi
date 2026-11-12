// Are the residual failures tied to the 5-tuple (source port) or random per attempt?
// Usage: node tuple.js host ip[,ip2] basePort count rounds gapMs
// Each (ip, localPort) pair is dialled once per round; sockets are closed with RST so the
// same local port can be reused immediately.
const net = require('net');
const tls = require('tls');

const [host, ipList, basePortS, countS, roundsS, gapS] = process.argv.slice(2);
const ips = ipList.split(',');
const basePort = Number(basePortS), count = Number(countS), rounds = Number(roundsS), gap = Number(gapS);
const TO = 3000, CONC = 10;

function attempt(ip, port) {
  return new Promise((res) => {
    let done = false;
    const t0 = Date.now();
    const s = net.connect({ host: ip, port: 443, localPort: port });
    let tcpAt = 0;
    const fin = (v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { s.resetAndDestroy(); } catch (e) { try { s.destroy(); } catch (_) {} }
      res(v);
    };
    const timer = setTimeout(() => fin(tcpAt ? 'TO' : 'SYN'), TO);
    s.on('error', (e) => fin(e.code === 'ECONNRESET' ? 'RST' : `E:${e.code}`));
    s.on('connect', () => {
      tcpAt = Date.now() - t0;
      const t = tls.connect({ socket: s, servername: host, ALPNProtocols: ['http/1.1'] });
      t.on('secureConnect', () => fin('ok'));
      t.on('error', (e) => fin(e.code === 'ECONNRESET' ? 'RST' : `E:${e.code || e.message}`));
    });
  });
}

async function pool(items, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

(async () => {
  const pairs = [];
  for (const ip of ips) for (let p = 0; p < count; p++) pairs.push({ ip, port: basePort + p });
  const table = pairs.map(() => []);
  for (let r = 0; r < rounds; r++) {
    const res = await pool(pairs, (x) => attempt(x.ip, x.port));
    res.forEach((v, k) => table[k].push(v));
    const bad = res.filter((v) => v !== 'ok').length;
    console.log(`round ${r + 1}: ${res.length - bad}/${res.length} ok`);
    if (r < rounds - 1) await new Promise((x) => setTimeout(x, gap));
  }
  let always = 0, sometimes = 0, never = 0;
  pairs.forEach((x, k) => {
    const fails = table[k].filter((v) => v !== 'ok').length;
    if (fails === 0) { never++; return; }
    if (fails === rounds) always++; else sometimes++;
    console.log(`  ${x.ip}:${x.port}  ${table[k].join(' ')}`);
  });
  const total = pairs.length * rounds;
  const failTotal = table.flat().filter((v) => v !== 'ok').length;
  console.log(`pairs=${pairs.length} neverFail=${never} alwaysFail=${always} mixed=${sometimes}  attempts=${total} fails=${failTotal} (${(100 * failTotal / total).toFixed(1)}%)`);
})();
