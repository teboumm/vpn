const net = require('net');
const crypto = require('crypto');
const http = require('http');
let Tun = null;
try {
  // optional dependency: only used on VPS with /dev/net/tun
  Tun = require('tuntap').Tun;
} catch (e) {
  console.warn('tuntap module not available — running without TUN support');
}

const NONCE_LEN = 12;
const TAG_LEN = 16;

function hexToBuf(hex) {
  return Buffer.from(hex.replace(/[^0-9a-f]/ig,''), 'hex');
}

const argv = require('minimist')(process.argv.slice(2));
const keyHex = argv.key || argv.k;
const tunIpArg = argv['tun-ip'] || argv['tunip'] || argv['tun_ip'] || argv.tunIp || '10.0.0.1/24';
const listenPort = argv.port || argv.p || 5555;

if (!keyHex) {
  console.error('Usage: node server.js --key <hexkey(64chars)> [--tun-ip 10.0.0.1/24] [--port 5555]');
  process.exit(1);
}

const key = hexToBuf(keyHex);
if (key.length !== 32) {
  console.error('Key must be 32 bytes (64 hex chars)');
  process.exit(1);
}

// parse tun ip/prefix
let tun = null;
let tunAddr = '10.0.0.1';
let tunMask = 24;
if (tunIpArg) {
  const parts = tunIpArg.split('/');
  tunAddr = parts[0] || tunAddr;
  if (parts[1]) {
    const m = parseInt(parts[1], 10);
    if (!isNaN(m) && m > 0 && m <= 32) tunMask = m;
  }
}

if (Tun) {
  try {
    tun = new Tun({ name: 'tun0', addr: tunAddr, mask: tunMask, mtu: 1500, persist: false });
    console.log('TUN created: tun0', `${tunAddr}/${tunMask}`);
  } catch (e) {
    console.error('Failed to create TUN device:', e.message);
    tun = null;
  }
} else {
  console.log('TUN unsupported in this environment');
}

let clientSocket = null;

function decryptFrame(buf) {
  // buf: nonce(12) | cipher | tag(16)
  const nonce = buf.slice(0, NONCE_LEN);
  const tag = buf.slice(buf.length - TAG_LEN);
  const cipher = buf.slice(NONCE_LEN, buf.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(cipher), decipher.final()]);
  return out;
}

function encryptFrame(plain) {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

// Read from TUN and send to connected client (only if tun exists)
if (tun) {
  tun.on('data', (buf) => {
    if (!clientSocket) return;
    const frame = encryptFrame(buf);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(frame.length, 0);
    clientSocket.write(Buffer.concat([len, frame]));
  });
}

const server = net.createServer((sock) => {
  console.log('Client connected from', sock.remoteAddress);
  clientSocket = sock;
  let state = { buf: Buffer.alloc(0) };

  sock.on('data', (data) => {
    console.log(data);
    
    state.buf = Buffer.concat([state.buf, data]);
    while (state.buf.length >= 4) {
      const payloadLen = state.buf.readUInt32BE(0);
      if (state.buf.length < 4 + payloadLen) break;
      const payload = state.buf.slice(4, 4 + payloadLen);
      state.buf = state.buf.slice(4 + payloadLen);
      try {
        const plain = decryptFrame(payload);
        console.log('Decrypted payload length', plain.length);
        if (tun) {
          try {
            tun.write(plain);
          } catch (e) {
            console.error('Error writing to TUN:', e.message);
          }
        } else {
          // No TUN available in this environment — support FETCH:<url> to proxy HTTP(S) for testing
          const text = plain.toString();
          if (text.startsWith('FETCH:')) {
            const url = text.slice(6).trim();
            console.log('Fetch request for', url);
            (async () => {
              try {
                const u = new URL(url);
                const proto = u.protocol === 'https:' ? require('https') : require('http');
                const opts = { method: 'GET', timeout: 5000 };
                const data = await new Promise((resolve, reject) => {
                  const req = proto.request(u, opts, (res) => {
                    let bufs = [];
                    let received = 0;
                    res.on('data', (chunk) => {
                      if (received < 65536) {
                        bufs.push(chunk);
                        received += chunk.length;
                      }
                    });
                    res.on('end', () => resolve(Buffer.concat(bufs)));
                  });
                  req.on('error', reject);
                  req.on('timeout', () => { req.destroy(new Error('timeout')); });
                  req.end();
                });
                const resp = Buffer.concat([Buffer.from('FETCHRESP:'), data.slice(0, 65536)]);
                const frame = encryptFrame(resp);
                const len = Buffer.alloc(4);
                len.writeUInt32BE(frame.length, 0);
                sock.write(Buffer.concat([len, frame]));
                console.log('Sent fetch response', resp.length);
              } catch (e) {
                console.error('Fetch error:', e.message);
                try {
                  const errb = Buffer.from('FETCHERR:' + e.message);
                  const frame = encryptFrame(errb);
                  const len = Buffer.alloc(4);
                  len.writeUInt32BE(frame.length, 0);
                  sock.write(Buffer.concat([len, frame]));
                } catch (ee) {
                  console.error('Error sending fetch error response:', ee.message);
                }
              }
            })();
          } else {
            try {
              const resp = Buffer.concat([Buffer.from('ECHO:'), plain]);
              const frame = encryptFrame(resp);
              const len = Buffer.alloc(4);
              len.writeUInt32BE(frame.length, 0);
              sock.write(Buffer.concat([len, frame]));
              console.log('Echoed response of length', resp.length);
            } catch (e) {
              console.error('Error sending echo response:', e.message);
            }
          }
        }
      } catch (e) {
        console.error('Decrypt/write error', e.message);
      }
    }
  });

  sock.on('close', () => { console.log('Client disconnected'); clientSocket = null; });
  sock.on('error', (e) => { console.error('Socket error', e.message); clientSocket = null; });
});

server.listen(listenPort, () => { console.log('Server listening on', listenPort); });

// small HTTP endpoint for status
http.createServer((req, res) => {
  if (req.url === '/status') {
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({tun: tun ? (`tun0:${tunAddr}/${tunMask}`) : 'unsupported', client: clientSocket?clientSocket.remoteAddress:null}));
  } else {
    res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('VPN proxy server\n');
  }
}).listen(8080, () => console.log('HTTP status on :8080'));
