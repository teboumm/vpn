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
const tunIp = argv['tun-ip'] || '10.0.0.1/24';
const listenPort = argv.port || 5555;

if (!keyHex) {
  console.error('Usage: node server.js --key <hexkey(64chars)> [--tun-ip 10.0.0.1/24] [--port 5555]');
  process.exit(1);
}

const key = hexToBuf(keyHex);
if (key.length !== 32) {
  console.error('Key must be 32 bytes (64 hex chars)');
  process.exit(1);
}

// create tun device if tuntap present
let tun = null;
if (Tun) {
  try {
    tun = new Tun({ name: 'tun0', addr: tunIp.split('/')[0], mask: 24, mtu: 1500, persist: false });
    console.log('TUN created: tun0', tunIp);
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
    state.buf = Buffer.concat([state.buf, data]);
    while (state.buf.length >= 4) {
      const payloadLen = state.buf.readUInt32BE(0);
      if (state.buf.length < 4 + payloadLen) break;
      const payload = state.buf.slice(4, 4 + payloadLen);
      state.buf = state.buf.slice(4 + payloadLen);
      try {
        const plain = decryptFrame(payload);
        tun.write(plain);
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
    res.end(JSON.stringify({tun:'tun0', client: clientSocket?clientSocket.remoteAddress:null}));
  } else {
    res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('VPN proxy server\n');
  }
}).listen(8080, () => console.log('HTTP status on :8080'));
