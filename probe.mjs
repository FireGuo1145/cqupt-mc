import crypto from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import readline from 'node:readline/promises';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { stdin, stdout } from 'node:process';
import { pathToFileURL } from 'node:url';
import { XMLParser } from 'fast-xml-parser';

export const IDS_ORIGIN = 'https://ids.cqupt.edu.cn';
export const LOGIN_URL = `${IDS_ORIGIN}/authserver/login`;
export const VALIDATE_URL = `${IDS_ORIGIN}/authserver/serviceValidate`;
const AES_CHARS = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';

/** Matches the public page's AES-CBC envelope: random 64-char prefix + password. */
export function encryptPassword(password, key, random = crypto.randomBytes) {
  const normalizedKey = String(key).trim();
  if (Buffer.byteLength(normalizedKey, 'utf8') !== 16) {
    throw new Error('Unexpected page encryption key size; refusing to submit.');
  }
  const randomString = (length) => Array.from(
    random(length), (n) => AES_CHARS[n % AES_CHARS.length],
  ).join('');
  const iv = Buffer.from(randomString(16), 'utf8');
  const prefix = randomString(64);
  const cipher = crypto.createCipheriv(
    'aes-128-cbc',
    Buffer.from(normalizedKey, 'utf8'),
    iv,
  );
  return Buffer.concat([
    cipher.update(prefix + password, 'utf8'),
    cipher.final(),
  ]).toString('base64');
}

function attrsFromInput(inputTag) {
  const attrs = {};
  const attrRe = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  for (const match of inputTag.matchAll(attrRe)) {
    attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return attrs;
}

export function parseLoginForm(html) {
  const form = html.match(/<form\b(?=[^>]*\bid\s*=\s*['"]pwdFromId['"])[^>]*>[\s\S]*?<\/form>/i)?.[0];
  if (!form) throw new Error('Could not find the password form; page layout may have changed.');
  const fields = {};
  for (const tag of form.matchAll(/<input\b[^>]*>/gi)) {
    const attrs = attrsFromInput(tag[0]);
    if (attrs.type?.toLowerCase() === 'checkbox' && !/\schecked(?:\s|=|\/?\s*>)/i.test(tag[0])) continue;
    if (attrs.name) fields[attrs.name] = attrs.value ?? '';
  }
  const salt = [...form.matchAll(/<input\b[^>]*>/gi)]
    .map((m) => attrsFromInput(m[0]))
    .find((a) => a.id === 'pwdEncryptSalt')?.value;
  if (!salt) throw new Error('Page encryption salt missing; refusing to submit.');
  if (!fields.execution || !fields._eventId) {
    throw new Error('Page execution fields missing; refusing to submit.');
  }
  return { fields, salt };
}

export function extractCasTicket(locationHeader, serviceUrl) {
  if (!locationHeader) return null;
  const service = new URL(serviceUrl);
  const target = new URL(locationHeader, LOGIN_URL);
  if (target.origin !== service.origin || target.pathname !== service.pathname) {
    return null;
  }
  const ticket = target.searchParams.get('ticket');
  if (!ticket) return null;
  target.searchParams.delete('ticket');
  if (target.search !== service.search) return null;
  return ticket;
}

function parseCasXml(xml) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('Unsafe XML response rejected.');
  const parsed = new XMLParser({
    removeNSPrefix: true,
    ignoreAttributes: false,
    processEntities: false,
    parseTagValue: false,
    trimValues: true,
  }).parse(xml);
  return parsed?.serviceResponse;
}

function visiblePageData(html) {
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '';
  const decode = (text) => text
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)));
  const strip = (text) => decode(text
    .replace(/<(script|style|noscript)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[\t\r\n ]+/g, ' ')
    .trim());
  return { title: strip(title).slice(0, 200), text: strip(html).slice(0, 4000) };
}

async function followSameOriginRedirects(response, initialUrl, request) {
  let currentResponse = response;
  let currentUrl = new URL(initialUrl);
  for (let hop = 0; hop < 8; hop += 1) {
    if (![301, 302, 303, 307, 308].includes(currentResponse.status)) {
      return { response: currentResponse, url: currentUrl.toString(), stopped: false };
    }
    const location = currentResponse.headers.get('location');
    if (!location) return { response: currentResponse, url: currentUrl.toString(), stopped: false };
    const nextUrl = new URL(location, currentUrl);
    if (nextUrl.origin !== IDS_ORIGIN) {
      return { response: null, url: null, stopped: true };
    }
    currentResponse = await request(nextUrl, {
      method: 'GET',
      headers: { referer: currentUrl.toString() },
    });
    currentUrl = nextUrl;
  }
  throw new Error('Too many redirects; stopped safely.');
}

async function promptHidden(label) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    throw new Error('Run in an interactive terminal, or set the documented environment variables.');
  }
  stdout.write(label);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding('utf8');
  return new Promise((resolve, reject) => {
    let value = '';
    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      stdout.write('\n');
    };
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\u0003') {
          cleanup();
          reject(new Error('Cancelled.'));
          return;
        }
        if (char === '\r' || char === '\n') {
          cleanup();
          resolve(value);
          return;
        }
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1);
        } else if (char >= ' ') {
          value += char;
        }
      }
    };
    stdin.on('data', onData);
  });
}

export async function runProbe({ username, password, serviceUrl, fetchImpl = fetch, captchaPrompt, captchaCode: suppliedCaptcha = '' }) {
  if (!username || !password) throw new Error('Username and password are required.');
  const service = serviceUrl ? new URL(serviceUrl) : null;
  if (service && service.protocol !== 'https:') throw new Error('CAS service callback must use HTTPS.');
  if (service && service.origin === IDS_ORIGIN) throw new Error('CAS service must be a separately registered application callback.');

  const cookieJar = new Map();
  const request = async (url, options = {}) => {
    const requestUrl = new URL(url);
    const headers = new Headers(options.headers ?? {});
    const cookieHeader = [...cookieJar.values()]
      .filter((cookie) => requestUrl.pathname === cookie.path || requestUrl.pathname.startsWith(`${cookie.path.replace(/\/$/, '')}/`))
      .filter((cookie) => !cookie.secure || requestUrl.protocol === 'https:')
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join('; ');
    if (cookieHeader) headers.set('cookie', cookieHeader);
    const response = await fetchImpl(url, { ...options, headers, redirect: 'manual' });
    for (const line of response.headers.getSetCookie?.() ?? []) {
      const parts = line.split(';');
      const pair = parts.shift().trim();
      const idx = pair.indexOf('=');
      if (idx > 0) {
        const attrs = Object.fromEntries(parts.map((part) => {
          const [key, ...rest] = part.trim().split('=');
          return [key.toLowerCase(), rest.join('=')];
        }));
        const defaultPath = requestUrl.pathname.slice(0, requestUrl.pathname.lastIndexOf('/')) || '/';
        const cookie = {
          name: pair.slice(0, idx),
          value: pair.slice(idx + 1),
          path: attrs.path || defaultPath,
          secure: parts.some((part) => part.trim().toLowerCase() === 'secure'),
        };
        cookieJar.set(`${cookie.name}|${cookie.path}`, cookie);
      }
    }
    return response;
  };

  const loginUrl = new URL(LOGIN_URL);
  if (service) loginUrl.searchParams.set('service', service.toString());
  const pageResponse = await request(loginUrl);
  if (!pageResponse.ok) throw new Error(`Login page returned HTTP ${pageResponse.status}.`);
  const pageHtml = await pageResponse.text();
  const { fields, salt } = parseLoginForm(pageHtml);

  // Same preflight called by the page after username entry. Never attempt to solve a challenge.
  const captchaCheck = new URL(`${IDS_ORIGIN}/authserver/checkNeedCaptcha.htl`);
  captchaCheck.searchParams.set('username', username);
  const checkResponse = await request(captchaCheck, { headers: { referer: loginUrl.toString() } });
  if (!checkResponse.ok) throw new Error(`Captcha preflight returned HTTP ${checkResponse.status}.`);
  const checkData = await checkResponse.json();
  let captchaCode = String(suppliedCaptcha || '').trim();
  if (checkData?.isNeed === true) {
    if (!captchaCode && typeof captchaPrompt !== 'function') {
      return { status: 'captcha-required', message: 'The identity provider requires a CAPTCHA; no image was fetched and no credentials were submitted.' };
    }
    const captchaUrl = new URL('/authserver/getCaptcha.htl', IDS_ORIGIN);
    captchaUrl.searchParams.set('_', String(Date.now()));
    const captchaResponse = await request(captchaUrl, { headers: { referer: loginUrl.toString() } });
    const imageType = captchaResponse.headers.get('content-type') || '';
    if (!captchaResponse.ok || !imageType.toLowerCase().startsWith('image/')) {
      return { status: 'captcha-image-unavailable', message: 'The identity provider required a CAPTCHA, but did not return an image; credentials were not submitted.' };
    }
    const imageBytes = Buffer.from(await captchaResponse.arrayBuffer());
    if (imageBytes.length === 0 || imageBytes.length > 5 * 1024 * 1024) {
      return { status: 'captcha-image-invalid', message: 'The CAPTCHA image was empty or exceeded the 5 MiB safety limit; credentials were not submitted.' };
    }
    const imageSubtype = imageType.split(';', 1)[0].split('/')[1].toLowerCase();
    const extension = ({ jpeg: '.jpg', png: '.png', gif: '.gif', webp: '.webp' })[imageSubtype] || '.img';
    const tempDir = await mkdtemp(join(tmpdir(), 'cqupt-captcha-'));
    const imagePath = join(tempDir, `captcha${extension}`);
    try {
      await writeFile(imagePath, imageBytes, { flag: 'wx' });
      captchaCode = String(await captchaPrompt(imagePath)).trim();
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
    if (!captchaCode) {
      return { status: 'captcha-cancelled', message: 'No CAPTCHA text was entered; credentials were not submitted.' };
    }
  }
  if (checkData?.isNeed !== false && checkData?.isNeed !== true) {
    return { status: 'unknown-preflight', message: 'The provider did not return an explicit no-CAPTCHA result; stopped without submitting credentials.' };
  }

  const form = new URLSearchParams();
  form.set('username', username);
  form.set('password', encryptPassword(password, salt));
  form.set('_eventId', fields._eventId);
  form.set('cllt', fields.cllt || 'userNameLogin');
  form.set('dllt', fields.dllt || 'generalLogin');
  form.set('execution', fields.execution);
  if (fields.lt) form.set('lt', fields.lt);
  if (fields.rememberMe) form.set('rememberMe', fields.rememberMe);
  if (captchaCode) form.set('captcha', captchaCode);
  const postUrl = new URL('/authserver/login', IDS_ORIGIN);
  if (service) postUrl.searchParams.set('service', service.toString());

  const loginResponse = await request(postUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
      origin: IDS_ORIGIN,
      referer: loginUrl.toString(),
    },
    body: form.toString(),
  });

  if (!service) {
    const final = await followSameOriginRedirects(loginResponse, postUrl, request);
    if (final.stopped) {
      return { status: 'external-redirect-stopped', message: 'The identity provider redirected outside its own origin; no external page was fetched.' };
    }
    const contentType = final.response.headers.get('content-type') || '';
    const textualResponse = /(?:text\/|json|xml|javascript)/i.test(contentType);
    const rawBody = textualResponse
      ? await final.response.text()
      : Buffer.from(await final.response.arrayBuffer());
    const pageHtml = textualResponse ? rawBody : '';
    const bodyBytes = textualResponse ? Buffer.byteLength(rawBody, 'utf8') : rawBody.byteLength;
    const pagePath = new URL(final.url).pathname;
    const isLoginPage = pagePath === '/authserver/login'
      || /id=["']pwdFromId["']|name=["']passwordText["']/i.test(pageHtml);
    const responseDetails = {
      finalHttpStatus: final.response.status,
      contentType: contentType || null,
      responseBodyBytes: bodyBytes,
      pagePath,
    };
    if (isLoginPage && final.response.status === 401) {
      return {
        status: captchaCode ? 'authentication-rejected' : 'credentials-incorrect',
        ...responseDetails,
        message: captchaCode
          ? 'The identity provider rejected the login after a CAPTCHA was submitted; the response does not distinguish wrong credentials from a wrong CAPTCHA.'
          : 'The identity provider returned HTTP 401 at the login page, matching the observed rejected-credentials response.',
      };
    }
    if (isLoginPage) {
      return {
        status: 'login-unconfirmed',
        ...responseDetails,
        message: 'The flow ended at the login page, but did not match the observed HTTP 401 rejection pattern.',
      };
    }
    const page = visiblePageData(pageHtml);
    if (pagePath === '/personalInfo/personCenter/index.html' && final.response.ok) {
      return {
        status: 'credentials-correct',
        ...responseDetails,
        pageTitle: page.title,
        pageText: page.text,
        note: 'This classification is based on the observed personal-center redirect; it is not an independent profile/API verification.',
      };
    }
    return {
      status: 'redirected-no-service',
      ...responseDetails,
      pageTitle: page.title,
      pageText: page.text,
      note: 'Page text is truncated to 4000 characters and may contain personal information; keep this output private.',
    };
  }

  const ticket = extractCasTicket(loginResponse.headers.get('location'), service.toString());
  if (!ticket) {
    return {
      status: 'login-unconfirmed-or-challenge',
      message: `No ticket-bearing redirect was observed (HTTP ${loginResponse.status}); do not treat this as authenticated.`,
    };
  }

  const validate = new URL(VALIDATE_URL);
  validate.searchParams.set('service', service.toString());
  validate.searchParams.set('ticket', ticket);
  const validationResponse = await request(validate, { headers: { accept: 'application/xml,text/xml' } });
  if (!validationResponse.ok) throw new Error(`Ticket validation returned HTTP ${validationResponse.status}.`);
  const responseXml = await validationResponse.text();
  const cas = parseCasXml(responseXml);
  const success = cas?.authenticationSuccess;
  if (!success) {
    return { status: 'ticket-rejected', message: 'CAS did not return authenticationSuccess.' };
  }
  const user = typeof success.user === 'string' ? success.user : success.user?.['#text'];
  if (!user) return { status: 'ticket-validated-no-user', message: 'Ticket validated, but no user identifier was returned.' };
  return { status: 'authenticated', user };
}

async function main() {
  console.log('Starting local CQUPT login probe. No credentials or cookies will be printed.');
  const serviceUrl = process.env.CAS_SERVICE_URL;
  const username = process.env.CQUPT_USERNAME || await promptHidden('Unified identity username: ');
  const password = process.env.CQUPT_PASSWORD || await promptHidden('Password (input hidden): ');
  console.log('Sending login flow requests; this may take a few seconds...');
  const result = await runProbe({
    username,
    password,
    serviceUrl,
    captchaPrompt: async (imagePath) => {
      console.log(`CAPTCHA required. Open this temporary image: ${basename(imagePath)} in ${resolve(imagePath, '..')}`);
      const prompt = readline.createInterface({ input: stdin, output: stdout });
      try {
        return await prompt.question('Enter the CAPTCHA text (leave blank to cancel): ');
      } finally {
        prompt.close();
      }
    },
  });
  // Never print the password, encrypted payload, cookies, raw HTML/XML, or CAS ticket.
  console.log(JSON.stringify(result, null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(`Probe stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
