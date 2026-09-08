/**
 * HTTP/1.x dissection.
 *
 * HTTP is the best teaching example for the top three OSI layers, because one
 * message contains all of them at once: the request line and headers are
 * Layer 7, Content-Type / charset / Content-Encoding are textbook Layer 6, and
 * Cookie / Authorization / Connection are the closest thing HTTP has to a
 * Layer 5 session. The dissector therefore emits three layer entries from one
 * byte range.
 */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { latin1Of, utf8Of } from '../bytes';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'];

export function looksLikeHttp(ctx: DissectContext, offset: number, length: number): boolean {
  const head = latin1Of(ctx.bytes, offset, Math.min(length, 16));
  if (head.startsWith('HTTP/1.')) return true;
  return METHODS.some((m) => head.startsWith(m + ' '));
}

interface HeaderEntry {
  name: string;
  value: string;
  offset: number;
  length: number;
}

const HEADER_NOTES: Record<string, string> = {
  host: 'Which virtual host this request is for. Mandatory in HTTP/1.1 — it is what lets one IP address serve thousands of websites.',
  'user-agent': 'A self-declared description of the client. Entirely under the client\'s control, so treat it as a hint, never as identification.',
  accept: 'Which media types the client can handle, with quality weights. The server uses it for content negotiation — a Layer 6 decision.',
  'accept-encoding': 'Which compression codecs the client can decode. The server picks one and names it in Content-Encoding.',
  'accept-language': 'Preferred natural languages. A surprisingly strong browser-fingerprinting signal.',
  connection: 'Whether to keep the TCP connection open for further requests. Persistent connections avoid paying for a new three-way handshake per object.',
  'content-length': 'Exact size of the body in bytes. Without it (or chunked encoding) the receiver cannot tell where one message ends and the next begins.',
  'content-type': 'The media type — and often the charset — of the body. This is the canonical Layer 6 field.',
  'content-encoding': 'A compression transform applied to the body that the receiver must reverse. Pure Layer 6.',
  'transfer-encoding': 'How the body is framed on the connection. "chunked" lets a server start responding before it knows the total length.',
  cookie: 'Session state the client is replaying back to the server. HTTP itself is stateless, so this is how a "logged-in session" is actually implemented.',
  'set-cookie': 'The server creating or updating client-side session state. Look at the Secure, HttpOnly and SameSite attributes — their absence is a common finding.',
  authorization: 'Credentials for this request. Basic authentication is only base64-encoded, not encrypted, so over plain HTTP it is equivalent to sending the password in clear text.',
  server: 'The server software. Version numbers here are exactly what an attacker uses to select an exploit.',
  date: 'When the server generated the response, in RFC 7231 format.',
  location: 'Where a 3xx redirect points.',
  etag: 'An opaque version tag for the resource, used for cache validation.',
  'cache-control': 'Caching directives for browsers and intermediate proxies.',
  'strict-transport-security': 'HSTS: tells the browser never to talk to this host over plain HTTP again for the given period.',
  referer: 'The page that linked here — misspelled in the original RFC and never corrected.',
};

export function dissectHttp(ctx: DissectContext, offset: number, length: number): void {
  const b = ctx.bytes;
  const limit = Math.min(b.length, offset + length);
  const text = latin1Of(b, offset, limit - offset);

  // Split the head from the body at the first blank line.
  let headerEnd = text.indexOf('\r\n\r\n');
  let separatorLength = 4;
  if (headerEnd < 0) {
    headerEnd = text.indexOf('\n\n');
    separatorLength = 2;
  }
  const headText = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
  const bodyOffset = headerEnd >= 0 ? offset + headerEnd + separatorLength : limit;
  const bodyLength = Math.max(0, limit - bodyOffset);

  const lines = headText.split(/\r?\n/);
  const startLine = lines[0] ?? '';
  const isResponse = startLine.startsWith('HTTP/');

  const fields: Field[] = [];
  let lineOffset = offset;
  const startLineLength = startLine.length;

  let summary = startLine;
  if (isResponse) {
    const m = /^HTTP\/(\d\.\d)\s+(\d{3})\s*(.*)$/.exec(startLine);
    const version = m?.[1] ?? '1.1';
    const status = Number(m?.[2] ?? 0);
    const reason = m?.[3] ?? '';
    summary = `${status} ${reason}`;
    ctx.term('http', String(status));
    fields.push(
      field({
        name: 'Status line',
        value: startLine,
        offset: lineOffset,
        length: startLineLength,
        layer: 7,
        whatText: 'The first line of a response: protocol version, status code, and a human-readable reason phrase.',
        children: [
          field({ name: 'Version', value: `HTTP/${version}`, offset: lineOffset, length: 8, layer: 7, key: 'http.version' }),
          field({
            name: 'Status Code',
            value: String(status),
            offset: lineOffset + 9,
            length: 3,
            layer: 7,
            key: 'http.status',
            why: explainStatus(status),
            note: status >= 500 ? 'error' : status >= 400 ? 'warn' : undefined,
          }),
          field({ name: 'Reason Phrase', value: reason, offset: lineOffset + 13, length: Math.max(0, reason.length), layer: 7, key: 'http.reason' }),
        ],
      }),
    );
  } else {
    const parts = startLine.split(' ');
    const method = parts[0] ?? '';
    const uri = parts[1] ?? '';
    const version = parts[2] ?? '';
    summary = `${method} ${uri}`;
    ctx.term('http', method.toLowerCase(), uri);
    fields.push(
      field({
        name: 'Request line',
        value: startLine,
        offset: lineOffset,
        length: startLineLength,
        layer: 7,
        whatText: 'The first line of a request: method, target resource, and protocol version, separated by single spaces.',
        children: [
          field({
            name: 'Method',
            value: method,
            offset: lineOffset,
            length: method.length,
            layer: 7,
            key: 'http.method',
            why: explainMethod(method),
          }),
          field({
            name: 'Request URI',
            value: uri,
            offset: lineOffset + method.length + 1,
            length: uri.length,
            layer: 7,
            key: 'http.uri',
            why: uri.includes('?')
              ? 'This URI carries a query string. Over plain HTTP every character of it — including anything that looks like a token or a password — is readable in this capture, and it is also written into server access logs and browser history.'
              : 'The path is relative to the host named in the Host header. Together they form the absolute URL.',
          }),
          field({ name: 'Version', value: version, offset: lineOffset + startLineLength - version.length, length: version.length, layer: 7, key: 'http.version' }),
        ],
      }),
    );
  }

  lineOffset += startLineLength + 2;

  const headers: HeaderEntry[] = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) {
      lineOffset += 2;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon > 0) {
      const name = line.slice(0, colon).trim();
      const value = line.slice(colon + 1).trim();
      headers.push({ name, value, offset: lineOffset, length: line.length });
      ctx.term(name.toLowerCase());
    }
    lineOffset += line.length + 2;
  }

  const headerFields = headers.map((h) =>
    field({
      name: h.name,
      value: h.value,
      offset: h.offset,
      length: h.length,
      layer: 7,
      key: 'http.header',
      whatText: HEADER_NOTES[h.name.toLowerCase()],
      why: headerWhy(h),
    }),
  );

  fields.push(
    field({
      name: `Headers (${headers.length})`,
      value: headers.map((h) => h.name).join(', '),
      offset: offset + startLineLength + 2,
      length: Math.max(0, bodyOffset - (offset + startLineLength + 2)),
      layer: 7,
      whatText: 'Header fields, one per line, terminated by a blank line. Everything HTTP can express beyond the method and URI is expressed here.',
    }),
  );
  fields.push(...headerFields);

  const get = (name: string) => headers.find((h) => h.name.toLowerCase() === name)?.value;
  const host = get('host');
  const contentType = get('content-type');
  const contentEncoding = get('content-encoding');
  const transferEncoding = get('transfer-encoding');
  const cookie = get('cookie') ?? get('set-cookie');
  const connection = get('connection');
  if (host) ctx.term(host);

  if (bodyLength > 0) {
    const bodyText = utf8Of(b, bodyOffset, Math.min(bodyLength, 512));
    fields.push(
      field({
        name: 'Message body',
        value:
          contentEncoding && contentEncoding !== 'identity'
            ? `${bodyLength} bytes, ${contentEncoding}-compressed (not decoded here)`
            : `${bodyLength} bytes${bodyText ? `: ${bodyText.slice(0, 200).replace(/\s+/g, ' ')}${bodyLength > 200 ? '...' : ''}` : ''}`,
        offset: bodyOffset,
        length: bodyLength,
        layer: 7,
        key: 'http.body',
        why: contentEncoding
          ? `The body is encoded with "${contentEncoding}". Those bytes are meaningless until the Layer 6 transform is reversed — which is exactly why Content-Encoding is a presentation-layer concern and not an application one.`
          : 'The payload itself: the document, form submission or API response the whole stack exists to deliver.',
      }),
    );
  }

  ctx.add({
    id: 'http',
    name: 'Hypertext Transfer Protocol',
    abbr: 'HTTP',
    layer: 7,
    summary: host && !isResponse ? `${summary} (Host: ${host})` : summary,
    offset,
    length: Math.max(0, bodyOffset - offset),
    fields,
    payload: bodyLength > 0 ? { offset: bodyOffset, length: bodyLength } : undefined,
  });

  ctx.info = isResponse ? `HTTP/1.x ${summary}${contentType ? `  (${contentType})` : ''}` : `${summary} HTTP/1.1`;

  /* ------------------------------------------------------- Layer 6 view — */
  const presentationFields: Field[] = [];
  const ctHeader = headers.find((h) => h.name.toLowerCase() === 'content-type');
  if (ctHeader) {
    const [mime, ...params] = ctHeader.value.split(';').map((s) => s.trim());
    presentationFields.push(
      field({
        name: 'MIME type',
        value: mime,
        offset: ctHeader.offset,
        length: ctHeader.length,
        layer: 6,
        key: 'http.content_type',
        why: `The receiver will hand these bytes to whatever handles "${mime}". Get this wrong and a browser renders your JSON as text, or worse, executes a file you meant it to download — which is why X-Content-Type-Options: nosniff exists.`,
      }),
    );
    const charset = params.find((p) => p.toLowerCase().startsWith('charset='));
    if (charset) {
      presentationFields.push(
        field({
          name: 'Character set',
          value: charset.split('=')[1],
          offset: ctHeader.offset,
          length: ctHeader.length,
          layer: 6,
          key: 'http.charset',
          why: 'Character encoding is the original presentation-layer problem: the same byte 0xE9 is "e-acute" in Latin-1 and half of a multi-byte sequence in UTF-8. Only this declaration tells the receiver which.',
        }),
      );
    }
  }
  const ceHeader = headers.find((h) => h.name.toLowerCase() === 'content-encoding');
  if (ceHeader) {
    presentationFields.push(
      field({
        name: 'Content encoding',
        value: ceHeader.value,
        offset: ceHeader.offset,
        length: ceHeader.length,
        layer: 6,
        key: 'http.content_encoding',
        why: `The body was compressed with ${ceHeader.value} before transmission and must be decompressed before it means anything. Compression is a representation transform, so it belongs to Layer 6 — not to HTTP semantics at Layer 7.`,
      }),
    );
  }
  const teHeader = headers.find((h) => h.name.toLowerCase() === 'transfer-encoding');
  if (teHeader) {
    presentationFields.push(
      field({
        name: 'Transfer encoding',
        value: teHeader.value,
        offset: teHeader.offset,
        length: teHeader.length,
        layer: 6,
        key: 'http.transfer_encoding',
        why: 'Chunked encoding frames the body as a series of hex-length-prefixed pieces ending with a zero-length chunk. Disagreement between servers and proxies about how to parse this framing is the basis of HTTP request smuggling.',
      }),
    );
  }
  presentationFields.push(
    field({
      name: 'Base encoding',
      value: 'US-ASCII text, CRLF line endings',
      offset,
      length: Math.max(0, bodyOffset - offset),
      layer: 6,
      synthetic: true,
      whatText:
        'HTTP/1.x headers are plain ASCII terminated by CRLF, which is why you can read this entire exchange in the hex pane\'s ASCII column with no dissector at all.',
      why: 'This human-readability is also the point of comparison for HTTP/2 and HTTP/3, which replaced it with a binary framing plus HPACK/QPACK header compression — faster for machines, unreadable without a decoder.',
    }),
  );

  ctx.add({
    id: 'http-presentation',
    name: 'Presentation layer (HTTP content negotiation)',
    abbr: 'HTTP',
    layer: 6,
    virtual: true,
    summary: [contentType, contentEncoding, transferEncoding].filter(Boolean).join(' | ') || 'ASCII text, no content transforms declared',
    offset,
    length: 0,
    fields: presentationFields,
  });

  /* ------------------------------------------------------- Layer 5 view — */
  const sessionFields: Field[] = [
    field({
      name: 'Protocol statefulness',
      value: 'HTTP is stateless',
      offset,
      length: 0,
      layer: 5,
      synthetic: true,
      key: 'http.session',
    }),
  ];
  const cookieHeader = headers.find((h) => ['cookie', 'set-cookie'].includes(h.name.toLowerCase()));
  if (cookieHeader) {
    sessionFields.push(
      field({
        name: cookieHeader.name,
        value: cookieHeader.value,
        offset: cookieHeader.offset,
        length: cookieHeader.length,
        layer: 5,
        whatText: HEADER_NOTES[cookieHeader.name.toLowerCase()],
        why: 'Here is the session layer, implemented by hand at Layer 7: an opaque token the client replays on every request so the server can find its state. Over plain HTTP anyone on the path can read and reuse it — which is what session hijacking is.',
        note: 'warn',
      }),
    );
  }
  const connHeader = headers.find((h) => h.name.toLowerCase() === 'connection');
  if (connHeader) {
    sessionFields.push(
      field({
        name: 'Connection',
        value: connHeader.value,
        offset: connHeader.offset,
        length: connHeader.length,
        layer: 5,
        key: 'http.keepalive',
        why:
          connHeader.value.toLowerCase().includes('keep-alive')
            ? 'The TCP connection stays open after this exchange, so later requests skip the three-way handshake. This is the nearest HTTP/1.1 gets to an explicit session.'
            : 'The connection will be closed once this message is complete, so any further request pays for a new handshake.',
      }),
    );
  }

  ctx.add({
    id: 'http-session',
    name: 'Session layer (as implemented by HTTP)',
    abbr: 'HTTP',
    layer: 5,
    virtual: true,
    summary: cookie ? 'Session tracked with a cookie token' : connection ? `Connection: ${connection}` : 'No explicit session state in this message',
    offset,
    length: 0,
    fields: sessionFields,
  });
}

function headerWhy(h: HeaderEntry): string | undefined {
  const n = h.name.toLowerCase();
  if (n === 'authorization' && /^basic /i.test(h.value)) {
    return 'Basic authentication is base64, which is an encoding, not encryption. Anyone holding this capture can decode the username and password in one step.';
  }
  if (n === 'host') return 'Over plain HTTP this is visible to everyone on the path. Its encrypted counterpart, TLS SNI, is still sent in clear text — which is why an eavesdropper can usually tell which site you visited even over HTTPS.';
  if (n === 'server') return 'Version banners like this are the first thing an attacker collects, and the first thing a hardening guide tells you to suppress.';
  if (n === 'content-length') return `The body is exactly ${h.value} bytes. This is how the receiver knows where this message ends and the next one on the same connection begins.`;
  return undefined;
}

function explainMethod(method: string): string {
  switch (method) {
    case 'GET':
      return 'GET asks for a representation of a resource and must not change server state. Because it is safe and idempotent, GET responses can be cached and GET requests can be retried freely.';
    case 'POST':
      return 'POST submits data for processing and may change state, so browsers warn before re-sending it and caches will not reuse it.';
    case 'PUT':
      return 'PUT replaces the resource at the target URI with the enclosed body. It is idempotent: sending it twice has the same effect as sending it once.';
    case 'DELETE':
      return 'DELETE removes the target resource.';
    case 'HEAD':
      return 'HEAD is GET without a body — used to check whether a resource exists or has changed without downloading it.';
    case 'OPTIONS':
      return 'OPTIONS asks what the server supports. Browsers send it automatically as a CORS preflight before certain cross-origin requests.';
    case 'CONNECT':
      return 'CONNECT asks a proxy to open a raw TCP tunnel — the mechanism that lets HTTPS traverse an HTTP proxy.';
    default:
      return 'An HTTP method: the verb describing what the client wants done with the resource.';
  }
}

function explainStatus(status: number): string {
  if (status >= 100 && status < 200) return 'A 1xx informational response. 101 Switching Protocols is how a WebSocket upgrade begins.';
  if (status >= 200 && status < 300) {
    return status === 200
      ? '200 OK: the request succeeded and the body contains the requested representation.'
      : `A 2xx success. ${status === 204 ? '204 means success with deliberately no body.' : status === 206 ? '206 is a partial response to a Range request — how resumable downloads and video seeking work.' : ''}`;
  }
  if (status >= 300 && status < 400) return `A 3xx redirect: the client should look in the Location header and try again. ${status === 301 ? '301 is permanent, so browsers cache it aggressively — a mistake here is hard to undo.' : status === 302 ? '302 is temporary.' : ''}`;
  if (status >= 400 && status < 500) {
    return status === 404
      ? '404 Not Found: the server understood the request but has nothing at that URI.'
      : status === 401
        ? '401 Unauthorized actually means unauthenticated — the client should retry with credentials.'
        : status === 403
          ? '403 Forbidden: the server understood and refuses. Authenticating differently will not help.'
          : 'A 4xx client error: the request itself was faulty, so retrying it unchanged will fail again.';
  }
  if (status >= 500) return 'A 5xx server error: the request may have been fine, but the server failed to handle it. Retrying can be worthwhile.';
  return 'A status code outside the defined ranges.';
}
