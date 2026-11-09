'use strict';
/**
 * xray-hanamii v2 — Node.js runtime wrapper for running xray (VLESS + WS)
 * on hanamii.jp via ZIP upload (hanamii cannot take a Docker image).
 *
 * What it does
 *  1. Finds the xray binary: bundled binary first (several candidate
 *     paths); if it is missing, downloads the pinned release from
 *     GitHub at runtime and extracts it with pure JS (see below).
 *  2. Writes an xray config from env vars (PORT / UUID / WS_PATH) and
 *     starts xray listening on 127.0.0.1:<a free local port>.
 *  3. Listens on $PORT (the port hanamii assigns). Plain HTTP requests
 *     (platform health checks) get 200. WebSocket upgrades are forwarded
 *     byte-for-byte to the local xray port — the handshake is never
 *     rewritten or re-parsed.
 *
 * Changes vs v1 (the v1 failure)
 *  v1 failed twice on hanamii with "spawn ENOENT": the wrapper
 *  could not find the bundled ./xray binary (cause unknown — the
 *  platform may drop the binary file during build, or run from a
 *  different working directory), fell back to a runtime download, and
 *  the fallback shelled out to an external archive command, which the
 *  hanamii runtime does not have. v2 fixes this three ways:
 *   a. Archive extraction is pure JS: the ZIP central directory is
 *      parsed by hand and entries are inflated with Node's built-in
 *      zlib. No external archive tool is invoked anywhere in this file.
 *   b. The runtime download uses Node's built-in fetch only (no curl),
 *      so the wrapper no longer depends on any external command except
 *      spawning xray itself.
 *   c. The bundled-binary lookup checks ./xray, __dirname/xray and
 *      process.cwd()/xray, chmods a found-but-not-executable binary
 *      before giving up on it, and logs the directory listings of both
 *      cwd and __dirname at startup so a missing binary can be
 *      diagnosed from the platform logs.
 *
 * Env vars
 *  PORT             port assigned by the platform (default 8080)
 *  UUID             VLESS user id (required)
 *  WS_PATH          WebSocket path, e.g. /ws-xxxx (default /ws)
 *  XRAY_PORT        local xray port (default: pick a free one)
 *  XRAY_VERSION     release to download if no bundled binary
 *                   (default v26.10.31 — the version verified locally)
 *  XRAY_HTTP_PROXY  optional http://user:pass@host:port — if set, the
 *                   xray outbound goes through that HTTP proxy.
 *                   Local-test-only knob; production uses freedom.
 *
 * No third-party dependencies: Node built-ins only.
 */

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const zlib = require('node:zlib');

const log = (...a) => console.log(new Date().toISOString(), '[wrapper]', ...a);
const logErr = (...a) => console.error(new Date().toISOString(), '[wrapper]', ...a);

const PORT = parseInt(process.env.PORT || '8080', 10);
const UUID = process.env.UUID || '';
const WS_PATH = process.env.WS_PATH || '/ws';
const XRAY_VERSION = process.env.XRAY_VERSION || 'v26.10.31';
const XRAY_HTTP_PROXY = process.env.XRAY_HTTP_PROXY || '';
const CONFIG_PATH = path.join(__dirname, 'xray-config.json');
const IDLE_TIMEOUT_MS = 10000; // close connections that send nothing

if (!UUID) {
  logErr('FATAL: UUID env var is required');
  process.exit(1);
}
if (!WS_PATH.startsWith('/')) {
  logErr('FATAL: WS_PATH must start with /');
  process.exit(1);
}
if (!Number.isInteger(PORT) || PORT <= 0 || PORT > 65535) {
  logErr('FATAL: invalid PORT:', process.env.PORT);
  process.exit(1);
}

function releaseUrl(version) {
  return `https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip`;
}

async function isExecutable(p) {
  try {
    await fs.promises.access(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

// --- pure-JS ZIP extraction (no external archive tool) -----------------
// Parses the End of Central Directory + central directory, then inflates
// the wanted entry with zlib. Handles stored (method 0) and deflate
// (method 8) entries, data descriptors (sizes are taken from the central
// directory, so they do not matter), and ZIP64 size fields.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function extractZipEntry(zipPath, wantedName, destPath) {
  const zip = await fs.promises.readFile(zipPath);
  // Find the End of Central Directory record (last 64 KiB + 22 bytes).
  const tailLen = Math.min(zip.length, 65557);
  const tailStart = zip.length - tailLen;
  let eocd = -1;
  for (let i = zip.length - 22; i >= tailStart; i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new Error('not a ZIP file (no end-of-central-directory record)');
  const totalEntries = zip.readUInt16LE(eocd + 10);
  const cdOffset = zip.readUInt32LE(eocd + 16);
  if (totalEntries === 0xffff || cdOffset === 0xffffffff) {
    throw new Error('ZIP64 archives are not supported by this extractor');
  }
  let p = cdOffset;
  let found = null;
  for (let i = 0; i < totalEntries; i++) {
    if (p + 46 > zip.length || zip.readUInt32LE(p) !== 0x02014b50) {
      throw new Error('corrupt central directory at entry ' + i);
    }
    const method = zip.readUInt16LE(p + 10);
    const crc = zip.readUInt32LE(p + 16);
    let compSize = zip.readUInt32LE(p + 20);
    let uncompSize = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const localOffset = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (compSize === 0xffffffff || uncompSize === 0xffffffff) {
      // ZIP64 extra field (0x0001): uncompressed size, then compressed size.
      let ep = p + 46 + nameLen;
      const extraEnd = ep + extraLen;
      while (ep + 4 <= extraEnd) {
        const id = zip.readUInt16LE(ep);
        const sz = zip.readUInt16LE(ep + 2);
        if (id === 0x0001) {
          let q = ep + 4;
          if (uncompSize === 0xffffffff) {
            uncompSize = Number(zip.readBigUInt64LE(q));
            q += 8;
          }
          if (compSize === 0xffffffff) {
            compSize = Number(zip.readBigUInt64LE(q));
            q += 8;
          }
          break;
        }
        ep += 4 + sz;
      }
    }
    if (name === wantedName || name.endsWith('/' + wantedName)) {
      found = { method, crc, compSize, uncompSize, localOffset };
      break;
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (!found) throw new Error(`entry '${wantedName}' not found in ${zipPath}`);
  if (found.method !== 0 && found.method !== 8) {
    throw new Error(`unsupported compression method ${found.method} for '${wantedName}'`);
  }
  const lh = found.localOffset;
  if (zip.readUInt32LE(lh) !== 0x04034b50) throw new Error('corrupt local file header');
  const lhNameLen = zip.readUInt16LE(lh + 26);
  const lhExtraLen = zip.readUInt16LE(lh + 28);
  const dataStart = lh + 30 + lhNameLen + lhExtraLen;
  const comp = zip.subarray(dataStart, dataStart + found.compSize);
  if (comp.length !== found.compSize) throw new Error('truncated ZIP entry data');
  const data = found.method === 8 ? zlib.inflateRawSync(comp) : Buffer.from(comp);
  if (data.length !== found.uncompSize) {
    throw new Error(`size mismatch after extraction: got ${data.length}, expected ${found.uncompSize}`);
  }
  if (crc32(data) !== found.crc) throw new Error('CRC32 mismatch after extraction');
  await fs.promises.writeFile(destPath, data);
  await fs.promises.chmod(destPath, 0o755);
  return data.length;
}

// --- xray binary -------------------------------------------------------

async function downloadRelease(url, dest) {
  const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(300000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} downloading ${url}`);
  const ws = fs.createWriteStream(dest);
  await new Promise((resolve, reject) => {
    Readable.fromWeb(res.body).pipe(ws).on('finish', resolve).on('error', reject);
  });
}

// Check the bundled binary in several places: the platform may run from
// a different working directory than the script's directory, or may
// strip the executable bit when it unpacks the upload.
async function findBundledBinary() {
  const candidates = [path.join(__dirname, 'xray'), path.resolve('xray'), path.join(process.cwd(), 'xray')];
  const seen = new Set();
  for (const p of candidates) {
    if (seen.has(p)) continue;
    seen.add(p);
    let st;
    try {
      st = await fs.promises.stat(p);
    } catch (e) {
      if (e.code !== 'ENOENT') log(`bundled-binary candidate ${p}: ${e.message}`);
      continue;
    }
    if (!st.isFile()) {
      log(`bundled-binary candidate ${p}: not a regular file`);
      continue;
    }
    // The platform may unpack the ZIP without the exec bit; fix it.
    try {
      await fs.promises.chmod(p, 0o755);
    } catch {
      /* ignore */
    }
    if (await isExecutable(p)) {
      log(`using bundled xray binary: ${p} (${st.size} bytes)`);
      return p;
    }
    log(`bundled-binary candidate ${p}: exists (${st.size} bytes) but not executable even after chmod`);
  }
  return null;
}

async function logDirectoryContents() {
  for (const dir of [process.cwd(), __dirname]) {
    try {
      const entries = await fs.promises.readdir(dir, { withFileTypes: true });
      log(
        `contents of ${dir}:`,
        entries.map((e) => (e.isDirectory() ? e.name + '/' : e.name)).join(', ') || '(empty)',
      );
    } catch (e) {
      log(`cannot list ${dir}: ${e.message}`);
    }
  }
}

// Prefer the bundled binary; fall back to a runtime download + pure-JS
// extraction. Never shells out to an external archive tool.
async function ensureXray() {
  const bundled = await findBundledBinary();
  if (bundled) return bundled;
  const url = releaseUrl(XRAY_VERSION);
  log('bundled xray binary not found, downloading', url);
  const zipPath = path.join(os.tmpdir(), 'xray-linux-64.zip');
  try {
    await downloadRelease(url, zipPath);
  } catch (e) {
    logErr('FATAL: failed to download xray release:', e.message);
    process.exit(1);
  }
  const dests = [path.join(__dirname, 'xray'), path.join(os.tmpdir(), 'xray')];
  let dest = null;
  for (const d of dests) {
    try {
      const n = await extractZipEntry(zipPath, 'xray', d);
      dest = d;
      log(`extracted xray (${n} bytes) to ${d} using built-in zlib`);
      break;
    } catch (e) {
      log(`extraction to ${d} failed: ${e.message}`);
    }
  }
  await fs.promises.unlink(zipPath).catch(() => {});
  if (!dest) {
    logErr('FATAL: could not extract xray from the downloaded release');
    process.exit(1);
  }
  if (!(await isExecutable(dest))) {
    logErr('FATAL: xray binary still not executable after download + extraction');
    process.exit(1);
  }
  log('downloaded and extracted xray', XRAY_VERSION);
  return dest;
}

function httpProxyOutbound(proxyUrl) {
  let u;
  try {
    u = new URL(proxyUrl);
  } catch {
    throw new Error('XRAY_HTTP_PROXY is not a valid URL: ' + proxyUrl);
  }
  const server = { address: u.hostname, port: parseInt(u.port || '8080', 10) };
  if (u.username) {
    server.users = [
      { user: decodeURIComponent(u.username), pass: decodeURIComponent(u.password || '') },
    ];
  }
  return { protocol: 'http', tag: 'proxy-out', settings: { servers: [server] } };
}

function buildConfig(xrayPort) {
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        port: xrayPort,
        listen: '127.0.0.1',
        protocol: 'vless',
        settings: { clients: [{ id: UUID }], decryption: 'none' },
        streamSettings: { network: 'ws', wsSettings: { path: WS_PATH } },
      },
    ],
    outbounds: [XRAY_HTTP_PROXY ? httpProxyOutbound(XRAY_HTTP_PROXY) : { protocol: 'freedom', tag: 'direct' }],
  };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function startXray(bin, configPath) {
  const child = spawn(bin, ['run', '-config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (d) => process.stdout.write('[xray] ' + d));
  child.stderr.on('data', (d) => process.stderr.write('[xray] ' + d));
  child.on('error', (e) => {
    logErr('FATAL: failed to spawn xray:', e.message);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    logErr(`xray exited (code=${code} signal=${signal}); wrapper exiting`);
    process.exit(code ?? 1);
  });
  return child;
}

async function waitForPort(port, timeoutMs = 15000) {
  const start = Date.now();
  for (;;) {
    const ok = await new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => {
        s.end();
        resolve(true);
      });
      s.once('error', () => resolve(false));
    });
    if (ok) return;
    if (Date.now() - start > timeoutMs) {
      throw new Error(`xray did not start listening on 127.0.0.1:${port} within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

// Raw TCP front door on $PORT. Sniffs the request head: a WebSocket
// upgrade is forwarded byte-for-byte to xray; anything else (health
// checks, stray probes) gets a plain 200.
function startFront(xrayPort) {
  const server = net.createServer((socket) => {
    socket.setTimeout(IDLE_TIMEOUT_MS, () => socket.destroy());
    let buf = Buffer.alloc(0);
    let decided = false;

    function onData(chunk) {
      if (decided) return;
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf('\r\n\r\n');
      if (end === -1) {
        if (buf.length > 16384) {
          socket.end(
            'HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n',
          );
        }
        return; // wait for the full header block
      }
      decided = true;
      socket.removeListener('data', onData);
      const headText = buf.subarray(0, end).toString('latin1');
      const isWsUpgrade =
        /^GET\s+\S+\s+HTTP\/1\.\d/i.test(headText) &&
        /connection\s*:[^\r\n]*upgrade/i.test(headText) &&
        /upgrade\s*:\s*websocket/i.test(headText);
      if (isWsUpgrade) {
        socket.setTimeout(0); // long-lived WS connection
        const upstream = net.connect(xrayPort, '127.0.0.1');
        upstream.once('connect', () => {
          upstream.write(buf); // original request bytes, untouched
          socket.pipe(upstream);
          upstream.pipe(socket);
        });
        upstream.on('error', (e) => {
          log('upstream error:', e.message);
          socket.destroy();
        });
        socket.on('error', () => upstream.destroy());
        upstream.on('close', () => socket.destroy());
        socket.on('close', () => upstream.destroy());
      } else {
        socket.end('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      }
    }

    socket.on('data', onData);
    socket.on('error', () => {});
  });

  server.on('error', (e) => {
    logErr('FATAL: front server error:', e.message);
    process.exit(1);
  });
  server.listen(PORT, '0.0.0.0', () => {
    log(`listening on 0.0.0.0:${PORT} (WS ${WS_PATH} -> 127.0.0.1:${xrayPort}, other HTTP -> 200)`);
  });
  return server;
}

async function main() {
  log(`starting (node=${process.version} PORT=${PORT} WS_PATH=${WS_PATH} xray=${XRAY_VERSION})`);
  log('cwd:', process.cwd());
  log('__dirname:', __dirname);
  await logDirectoryContents();
  const bin = await ensureXray();
  const xrayPort = process.env.XRAY_PORT
    ? parseInt(process.env.XRAY_PORT, 10)
    : await freePort();
  if (!Number.isInteger(xrayPort) || xrayPort <= 0 || xrayPort > 65535) {
    logErr('FATAL: invalid XRAY_PORT:', process.env.XRAY_PORT);
    process.exit(1);
  }
  const config = buildConfig(xrayPort);
  let configPath = CONFIG_PATH;
  try {
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2));
  } catch {
    configPath = path.join(os.tmpdir(), 'xray-config.json');
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2));
  }
  log('xray config written to', configPath);
  const child = startXray(bin, configPath);
  const shutdown = () => {
    try {
      child.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  await waitForPort(xrayPort);
  log('xray is listening on 127.0.0.1:' + xrayPort);
  startFront(xrayPort);
}

main().catch((e) => {
  logErr('FATAL:', e.message);
  process.exit(1);
});
