const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const KEYFILE = process.env.KEYFILE || '/tmp/vpn_test_key';
const key = Buffer.from(fs.readFileSync(KEYFILE,'utf8').trim(), 'hex');
const NONCE_LEN = 12;
const TAG_LEN = 16;

function encryptFrame(plain) {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

function decryptFrame(buf) {
  const nonce = buf.slice(0, NONCE_LEN);
  const tag = buf.slice(buf.length - TAG_LEN);
  const cipher = buf.slice(NONCE_LEN, buf.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(cipher), decipher.final()]);
}

const host = process.argv[2] || '127.0.0.1';
const port = parseInt(process.argv[3]||'5555',10);

const sock = net.createConnection({host, port}, () => {
  console.log('connected');
  const payload = Buffer.from(process.argv[4] || 'hello from test client');
  const frame = encryptFrame(payload);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(frame.length, 0);
  sock.write(Buffer.concat([len, frame]));
  console.log('sent encrypted payload');
});

let state = Buffer.alloc(0);
sock.on('data', (data) => {
  state = Buffer.concat([state, data]);
  while (state.length >= 4) {
    const l = state.readUInt32BE(0);
    if (state.length < 4 + l) break;
    const payload = state.slice(4, 4 + l);
    state = state.slice(4 + l);
    try {
      const plain = decryptFrame(payload);
      console.log('received response:', plain.toString());
    } catch (e) {
      console.error('decrypt error', e.message);
    }
  }
});

sock.on('end', ()=> console.log('ended'));
sock.on('error', (e)=> console.error('sock err', e.message));
