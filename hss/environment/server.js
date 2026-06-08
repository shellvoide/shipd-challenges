const crypto = require('node:crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const parse = require('url-parse');
const { visit } = require('./worker');

const app = express();
const port = Number(process.env.PORT || 1337);
const sessionCookie = crypto.randomBytes(24).toString('hex');
const protectedValue = `HSS-${crypto.randomBytes(18).toString('hex').toUpperCase()}`;
const collectionTag = crypto.randomBytes(16).toString('hex');
const collected = [];

app.disable('x-powered-by');
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.text({ type: '*/*', limit: '32kb' }));

function page(body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>HSS</title></head><body>${body}</body></html>`;
}

app.get('/', (req, res) => {
  res.type('html').send(page('<h1>HSS</h1><a href="/report">Report</a>'));
});

app.get('/view', (req, res) => {
  const link = req.query.link;
  if (typeof link !== 'string') {
    res.type('html').send(page('<p>Nothing selected.</p>'));
    return;
  }

  let target = '#';
  try {
    const data = JSON.parse(`{"username":"guest","link":"${link}"}`);
    const url = parse(data.link, true);
    if (url.hostname === 'admin.pk' && data.username === 'admin' && data.pass === 'P@ss') {
      target = url.href;
    }
  } catch {
    target = '#';
  }

  res.type('html').send(page(`<script>location.href = ${JSON.stringify(target)}.replaceAll('&#34;', '"').replaceAll('&#39;', "'");</script>`));
});

app.get('/report', (req, res) => {
  res.type('html').send(page('<form method="POST"><input name="parameters"><button>Submit</button></form>'));
});

app.get('/review/meta', (req, res) => {
  if (req.cookies.session !== sessionCookie) {
    res.status(401).send('not available');
    return;
  }
  res.json({ channel: collectionTag });
});

app.post('/report', (req, res) => {
  const parameters = req.body && req.body.parameters;
  if (typeof parameters !== 'string') {
    res.status(400).send('invalid report');
    return;
  }
  visit(parameters, sessionCookie).catch((error) => console.error(error));
  res.send('queued');
});

app.get('/review/value', (req, res) => {
  if (req.cookies.session !== sessionCookie) {
    res.status(401).send('not available');
    return;
  }
  res.type('text/plain').send(protectedValue);
});

app.post('/collect', (req, res) => {
  const value = typeof req.body === 'string' ? req.body.trim() : '';
  const parts = value.split(':');
  const tag = parts.shift() || '';
  const nonce = parts.shift() || '';
  const recovered = parts.join(':');
  if (tag === collectionTag && /^[a-f0-9]{24}$/.test(nonce) && recovered.length > 0 && recovered.length < 128) {
    collected.unshift({ value: recovered, nonce, time: Date.now() });
    collected.splice(8);
  }
  res.send('ok');
});

app.get('/collect', (req, res) => {
  res.json({ items: collected.slice(0, 4) });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`HSS listening on ${port}`);
});
