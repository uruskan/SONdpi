// Usage: node probe.js host=ip [host=ip ...]
// For every target, two TLS clients connect to the pinned real IP:
//   node = OpenSSL 3.5 (X25519MLKEM768 key share, large ClientHello like Chromium/Discord)
//   curl = Schannel (small ClientHello)
const https = require('https');
const { execFile } = require('child_process');

const TO = Number(process.env.GD_PROBE_TO) || 5000;
const targets = process.argv.slice(2).map((s) => {
  const i = s.indexOf('=');
  return { h: s.slice(0, i), ip: s.slice(i + 1) };
});

function nodeProbe(t) {
  return new Promise((res) => {
    const t0 = Date.now();
    let done = false;
    const fin = (v) => { if (!done) { done = true; res(v); } };
    const req = https.request(
      {
        host: t.ip, port: 443, servername: t.h, path: '/', method: 'GET',
        headers: { Host: t.h, 'User-Agent': 'Mozilla/5.0' }, timeout: TO, agent: false,
      },
      (r) => { r.resume(); fin(`${r.statusCode}/${Date.now() - t0}ms`); req.destroy(); }
    );
    req.on('timeout', () => { fin('FAIL(timeout)'); req.destroy(); });
    req.on('error', (e) => fin(`FAIL(${e.code || e.message})`));
    setTimeout(() => { fin('FAIL(hard-timeout)'); req.destroy(); }, TO + 1000);
    req.end();
  });
}

function curlProbe(t) {
  return new Promise((res) => {
    execFile(
      'curl.exe',
      ['-4', '-s', '-m', String(TO / 1000), '-o', 'NUL', '-w', '%{http_code}/%{time_total}s',
        '--resolve', `${t.h}:443:${t.ip}`, `https://${t.h}/`],
      { timeout: TO + 2000, windowsHide: true },
      (err, stdout) => {
        const s = String(stdout || '').trim();
        res(s.startsWith('000') || !s ? `FAIL(${s || (err && err.code) || 'none'})` : s);
      }
    );
  });
}

(async () => {
  const rows = await Promise.all(
    targets.map(async (t) => {
      const [n, c] = await Promise.all([nodeProbe(t), curlProbe(t)]);
      return `${t.h.padEnd(20)} bigCH(node)=${n.padEnd(20)} smallCH(curl)=${c}`;
    })
  );
  console.log(rows.join('\n'));
  process.exit(0);
})();
