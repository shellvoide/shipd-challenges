const puppeteer = require('puppeteer-core');

async function visit(parameters, sessionCookie) {
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
    ],
  });

  try {
    const page = await browser.newPage();
    await page.setCookie({
      name: 'session',
      value: sessionCookie,
      domain: '127.0.0.1',
      httpOnly: true,
    });
    await page.goto(`http://127.0.0.1:1337/view?link=${encodeURIComponent(parameters)}`, {
      waitUntil: 'networkidle2',
      timeout: 8000,
    }).catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, 1500));
  } finally {
    await browser.close();
  }
}

module.exports = { visit };
