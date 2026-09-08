/**
 * TLS record and handshake dissection.
 *
 * This is the heart of the Layer 5 / Layer 6 demonstration. A ClientHello
 * contains, in one contiguous byte range: a session identifier and session
 * tickets (Layer 5 — establishing and resuming a dialogue), the cipher and
 * compression negotiation that decides how everything above will be
 * represented (Layer 6), and the ALPN and SNI extensions that name the
 * Layer 7 protocol and host.
 */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { hex, hexPreview, readU16BE, readU24BE } from '../bytes';

const CONTENT_TYPES: Record<number, string> = {
  20: 'Change Cipher Spec',
  21: 'Alert',
  22: 'Handshake',
  23: 'Application Data',
  24: 'Heartbeat',
};

const VERSIONS: Record<number, string> = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
};

const HANDSHAKE_TYPES: Record<number, string> = {
  0: 'Hello Request',
  1: 'Client Hello',
  2: 'Server Hello',
  4: 'New Session Ticket',
  5: 'End of Early Data',
  8: 'Encrypted Extensions',
  11: 'Certificate',
  12: 'Server Key Exchange',
  13: 'Certificate Request',
  14: 'Server Hello Done',
  15: 'Certificate Verify',
  16: 'Client Key Exchange',
  20: 'Finished',
};

const CIPHER_SUITES: Record<number, string> = {
  0x1301: 'TLS_AES_128_GCM_SHA256 (TLS 1.3)',
  0x1302: 'TLS_AES_256_GCM_SHA384 (TLS 1.3)',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (obsolete)',
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV (signalling value, not a real suite)',
};

const GROUPS: Record<number, string> = {
  23: 'secp256r1 (NIST P-256)',
  24: 'secp384r1',
  25: 'secp521r1',
  29: 'x25519',
  30: 'x448',
  256: 'ffdhe2048',
  257: 'ffdhe3072',
  0x11ec: 'X25519MLKEM768 (post-quantum hybrid)',
};

const EXTENSIONS: Record<number, string> = {
  0: 'server_name (SNI)',
  1: 'max_fragment_length',
  5: 'status_request (OCSP stapling)',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  16: 'application_layer_protocol_negotiation (ALPN)',
  18: 'signed_certificate_timestamp',
  21: 'padding',
  22: 'encrypt_then_mac',
  23: 'extended_master_secret',
  27: 'compress_certificate',
  35: 'session_ticket',
  41: 'pre_shared_key',
  42: 'early_data',
  43: 'supported_versions',
  45: 'psk_key_exchange_modes',
  49: 'post_handshake_auth',
  50: 'signature_algorithms_cert',
  51: 'key_share',
  0xff01: 'renegotiation_info',
};

export function looksLikeTls(ctx: DissectContext, offset: number, length: number): boolean {
  if (length < 5) return false;
  const type = ctx.bytes[offset];
  const version = readU16BE(ctx.bytes, offset + 1);
  const recLen = readU16BE(ctx.bytes, offset + 3);
  return (
    type >= 20 &&
    type <= 24 &&
    version >= 0x0300 &&
    version <= 0x0304 &&
    recLen > 0 &&
    recLen <= 16640
  );
}

interface TlsSummary {
  records: string[];
  sni?: string;
  alpn?: string[];
  sessionId?: string;
  negotiatedVersion?: string;
  cipherSuite?: string;
  ticketBytes?: number;
  handshakeTypes: string[];
  encryptedBytes: number;
}

export function dissectTls(ctx: DissectContext, offset: number, length: number): void {
  const b = ctx.bytes;
  const limit = Math.min(b.length, offset + length);
  const fields: Field[] = [];
  const summary: TlsSummary = { records: [], handshakeTypes: [], encryptedBytes: 0 };

  let cursor = offset;
  let recordIndex = 0;
  let truncated = false;

  while (cursor + 5 <= limit && recordIndex < 16) {
    const type = b[cursor];
    const version = readU16BE(b, cursor + 1);
    const recLen = readU16BE(b, cursor + 3);
    if (!CONTENT_TYPES[type]) break;
    const bodyStart = cursor + 5;
    const bodyEnd = Math.min(limit, bodyStart + recLen);
    if (bodyStart + recLen > limit) truncated = true;

    recordIndex++;
    const typeName = CONTENT_TYPES[type];
    summary.records.push(typeName);

    const recordFields: Field[] = [
      field({
        name: 'Content Type',
        value: `${type} (${typeName})`,
        offset: cursor,
        length: 1,
        layer: 6,
        key: 'tls.record.type',
        why:
          type === 23
            ? 'Application Data: everything inside is encrypted. From here on a capture shows only sizes and timing — which is still enough for traffic analysis, but not for reading content.'
            : type === 22
              ? 'A handshake record. In TLS 1.2 the whole handshake is in clear text; in TLS 1.3 only the first two messages are, and everything after ServerHello is encrypted.'
              : undefined,
      }),
      field({
        name: 'Version',
        value: `${hex(version, 4)} (${VERSIONS[version] ?? 'unknown'})`,
        offset: cursor + 1,
        length: 2,
        layer: 6,
        key: 'tls.record.version',
        why:
          version === 0x0301
            ? 'The record layer says TLS 1.0 even on a modern connection. This is deliberate: some middleboxes drop records with a higher version here, so clients pin it low and negotiate the real version inside the handshake.'
            : undefined,
      }),
      field({
        name: 'Length',
        value: `${recLen} bytes`,
        offset: cursor + 3,
        length: 2,
        layer: 6,
        key: 'tls.record.length',
      }),
    ];

    if (type === 22 && bodyEnd > bodyStart) {
      recordFields.push(...dissectHandshake(ctx, bodyStart, bodyEnd, summary));
    } else if (type === 23) {
      summary.encryptedBytes += recLen;
      recordFields.push(
        field({
          name: 'Encrypted application data',
          value: `${recLen} bytes: ${hexPreview(b, bodyStart, Math.min(recLen, 16), 16)}`,
          offset: bodyStart,
          length: Math.max(0, bodyEnd - bodyStart),
          layer: 6,
          key: 'payload.encrypted',
          why: 'This is where Layer 7 would be, and it is unreadable by design. What a capture still tells you: the peer, the SNI from the handshake, the sizes and timing of each record — enough to infer which page was loaded on many sites.',
        }),
      );
    } else if (type === 21 && bodyEnd - bodyStart >= 2) {
      const level = b[bodyStart];
      const desc = b[bodyStart + 1];
      recordFields.push(
        field({
          name: 'Alert',
          value: `level ${level === 1 ? 'warning' : level === 2 ? 'fatal' : level}, description ${desc}`,
          offset: bodyStart,
          length: 2,
          layer: 6,
          whatText: 'A TLS alert. Level 2 is fatal and ends the connection immediately.',
          why: desc === 0 ? 'close_notify: an orderly shutdown of the TLS session.' : `Alert description ${desc}. Common values: 40 handshake_failure, 42 bad_certificate, 48 unknown_ca, 51 decrypt_error, 70 protocol_version.`,
          note: level === 2 ? 'error' : 'warn',
        }),
      );
    } else if (type === 20) {
      recordFields.push(
        field({
          name: 'Change Cipher Spec',
          value: '1',
          offset: bodyStart,
          length: Math.max(0, bodyEnd - bodyStart),
          layer: 6,
          whatText: 'The signal that everything after this point is encrypted with the newly negotiated keys.',
          why: 'In TLS 1.3 this record is vestigial — it is sent purely so middleboxes that expect the TLS 1.2 shape do not break the connection.',
        }),
      );
    }

    fields.push(
      field({
        name: `TLS record ${recordIndex}: ${typeName}`,
        value: `${typeName}, ${VERSIONS[version] ?? hex(version, 4)}, ${recLen} bytes`,
        offset: cursor,
        length: Math.min(5 + recLen, limit - cursor),
        layer: 6,
        whatText: 'Every TLS message is wrapped in a 5-byte record header: content type, version, length. This framing is what turns TCP\'s byte stream back into discrete messages.',
        children: recordFields,
      }),
    );

    cursor = bodyStart + recLen;
  }

  if (recordIndex === 0) return;
  if (truncated) ctx.warn('A TLS record extends beyond the captured bytes; it continues in a later segment.');

  ctx.term('tls', 'ssl', summary.sni, ...(summary.alpn ?? []));

  const headline =
    summary.handshakeTypes.length > 0
      ? summary.handshakeTypes.join(', ')
      : summary.records.join(', ');

  ctx.add({
    id: 'tls',
    name: 'Transport Layer Security',
    abbr: 'TLS',
    layer: 6,
    alsoLayers: [5],
    summary: `${headline}${summary.sni ? ` — ${summary.sni}` : ''}`,
    offset,
    length: Math.min(cursor, limit) - offset,
    fields,
  });

  ctx.info = `TLS ${headline}${summary.sni ? ` (SNI: ${summary.sni})` : ''}`;

  /* --------------------------------------------- Layer 5: TLS as session — */
  const sessionFields: Field[] = [];
  if (summary.sessionId !== undefined) {
    sessionFields.push(
      field({
        name: 'Session ID',
        value: summary.sessionId || '(empty)',
        offset,
        length: 0,
        layer: 5,
        synthetic: true,
        key: 'tls.session_id',
        why: summary.sessionId
          ? 'A non-empty session ID means the client is offering to resume a previous session, or (in TLS 1.3) is sending a fake one for middlebox compatibility. Resumption skips the expensive public-key operations entirely.'
          : 'An empty session ID means there is nothing to resume: this is a full handshake from scratch.',
      }),
    );
  }
  if (summary.ticketBytes !== undefined) {
    sessionFields.push(
      field({
        name: 'Session ticket',
        value: `${summary.ticketBytes} bytes`,
        offset,
        length: 0,
        layer: 5,
        synthetic: true,
        key: 'tls.ticket',
      }),
    );
  }
  sessionFields.push(
    field({
      name: 'Session role',
      value: 'TLS provides genuine Layer 5 services',
      offset,
      length: 0,
      layer: 5,
      synthetic: true,
      whatText:
        'TLS is the clearest case in the whole TCP/IP stack of a protocol doing real session-layer work: it establishes a dialogue, holds negotiated state on both sides, can resume that state on a brand-new TCP connection, and tears the dialogue down with close_notify.',
      why: 'That resumption ability is the giveaway. A session that can survive the death of its TCP connection is, by definition, not the transport layer\'s session.',
    }),
  );

  ctx.add({
    id: 'tls-session',
    name: 'Session layer (provided by TLS)',
    abbr: 'TLS',
    layer: 5,
    virtual: true,
    summary: summary.sessionId ? `Session ID ${summary.sessionId.slice(0, 16)}...` : 'Full handshake, no session to resume',
    offset,
    length: 0,
    fields: sessionFields,
  });

  /* --------------------------- Layer 7 hint: what is inside the tunnel? — */
  if (summary.alpn?.length) {
    ctx.add({
      id: 'tls-alpn',
      name: 'Application layer (negotiated inside TLS)',
      abbr: 'TLS',
      layer: 7,
      virtual: true,
      summary: `ALPN offers: ${summary.alpn.join(', ')}`,
      offset,
      length: 0,
      fields: [
        field({
          name: 'Application protocol(s)',
          value: summary.alpn.join(', '),
          offset,
          length: 0,
          layer: 7,
          synthetic: true,
          key: 'tls.ext.alpn',
          why: 'This is Layer 7 announcing itself before Layer 6 has finished setting up — one round trip saved. Without ALPN the client would have to complete the handshake and then guess or ask.',
        }),
      ],
    });
  }
}

function dissectHandshake(ctx: DissectContext, start: number, end: number, summary: TlsSummary): Field[] {
  const b = ctx.bytes;
  const out: Field[] = [];
  let cursor = start;
  let guard = 0;

  while (cursor + 4 <= end && guard++ < 8) {
    const hsType = b[cursor];
    const hsLen = readU24BE(b, cursor + 1);
    const bodyStart = cursor + 4;
    const bodyEnd = Math.min(end, bodyStart + hsLen);
    const name = HANDSHAKE_TYPES[hsType] ?? `handshake type ${hsType}`;
    summary.handshakeTypes.push(name);

    const children: Field[] = [
      field({
        name: 'Handshake Type',
        value: `${hsType} (${name})`,
        offset: cursor,
        length: 1,
        layer: 6,
        key: 'tls.handshake.type',
      }),
      field({ name: 'Length', value: `${hsLen} bytes`, offset: cursor + 1, length: 3, layer: 6, whatText: 'Length of this handshake message, not counting the 4-byte handshake header.' }),
    ];

    if ((hsType === 1 || hsType === 2) && bodyEnd - bodyStart >= 34) {
      children.push(...dissectHello(ctx, bodyStart, bodyEnd, hsType === 1, summary));
    } else if (hsType === 11) {
      children.push(
        field({
          name: 'Certificate chain',
          value: `${hsLen} bytes of DER-encoded X.509`,
          offset: bodyStart,
          length: Math.max(0, bodyEnd - bodyStart),
          layer: 6,
          whatText:
            'The server\'s certificate chain, each certificate DER-encoded using ASN.1 Basic Encoding Rules — a tag/length/value structure that is the classic textbook example of a Layer 6 presentation format.',
          why: 'ASN.1 BER/DER is exactly what the OSI model had in mind for the presentation layer: an abstract data structure with a defined transfer syntax, independent of the machine that produced it.',
        }),
      );
    } else if (hsType === 4) {
      summary.ticketBytes = hsLen;
      children.push(
        field({
          name: 'Session ticket',
          value: `${hsLen} bytes`,
          offset: bodyStart,
          length: Math.max(0, bodyEnd - bodyStart),
          layer: 5,
          key: 'tls.ticket',
          why: 'The server has encrypted its own session state and handed it to the client to hold. Presenting the ticket later resumes the session without the server having to remember anything — stateless session state.',
        }),
      );
    } else if (bodyEnd > bodyStart) {
      children.push(
        field({
          name: 'Message body',
          value: hexPreview(b, bodyStart, bodyEnd - bodyStart),
          offset: bodyStart,
          length: bodyEnd - bodyStart,
          layer: 6,
          whatText: 'The body of this handshake message.',
        }),
      );
    }

    out.push(
      field({
        name: `Handshake: ${name}`,
        value: `${hsLen} bytes`,
        offset: cursor,
        length: Math.min(4 + hsLen, end - cursor),
        layer: 6,
        whatText: 'One handshake message. Several can share a single TLS record, and one message can be split across records.',
        children,
      }),
    );

    cursor = bodyStart + hsLen;
  }

  return out;
}

function dissectHello(ctx: DissectContext, start: number, end: number, isClient: boolean, summary: TlsSummary): Field[] {
  const b = ctx.bytes;
  const out: Field[] = [];
  let o = start;

  const version = readU16BE(b, o);
  out.push(
    field({
      name: 'Legacy Version',
      value: `${hex(version, 4)} (${VERSIONS[version] ?? 'unknown'})`,
      offset: o,
      length: 2,
      layer: 6,
      key: 'tls.version',
      why:
        version === 0x0303
          ? 'A TLS 1.3 handshake also puts 0x0303 (TLS 1.2) here for compatibility. The real version is in the supported_versions extension — look for 0x0304 further down.'
          : undefined,
    }),
  );
  o += 2;

  out.push(
    field({
      name: isClient ? 'Client Random' : 'Server Random',
      value: hexPreview(b, o, 32, 12),
      offset: o,
      length: 32,
      layer: 6,
      key: 'tls.random',
      why: 'These 32 bytes are mixed into the key schedule so that two handshakes never derive the same keys, even between the same pair of hosts with the same certificate. In TLS 1.3 the last 8 bytes of the server random also carry a downgrade-protection sentinel.',
    }),
  );
  o += 32;

  const sessionIdLen = b[o];
  const sessionIdHex = hexPreview(b, o + 1, sessionIdLen, 32).replace(/ /g, '');
  if (isClient || sessionIdLen > 0) summary.sessionId = sessionIdLen ? sessionIdHex : '';
  out.push(
    field({
      name: 'Session ID',
      value: sessionIdLen === 0 ? '(empty, length 0)' : `${sessionIdLen} bytes: ${hexPreview(b, o + 1, sessionIdLen, 12)}`,
      offset: o,
      length: 1 + sessionIdLen,
      layer: 5,
      key: 'tls.session_id',
      why:
        sessionIdLen === 0
          ? 'No session to resume, so this is a full handshake including the public-key operations.'
          : 'A TLS 1.3 client fills this with 32 random bytes it never intends to use, purely so the exchange looks like TLS 1.2 to middleboxes that would otherwise drop it. In a genuine TLS 1.2 handshake the same field really does identify a cached session.',
    }),
  );
  o += 1 + sessionIdLen;

  if (isClient) {
    const csLen = readU16BE(b, o);
    const suites: string[] = [];
    const suiteFields: Field[] = [];
    for (let i = 0; i + 1 < csLen && o + 2 + i + 1 < end; i += 2) {
      const cs = readU16BE(b, o + 2 + i);
      suites.push(CIPHER_SUITES[cs] ?? hex(cs, 4));
      suiteFields.push(
        field({
          name: CIPHER_SUITES[cs] ?? `Unknown suite ${hex(cs, 4)}`,
          value: hex(cs, 4),
          offset: o + 2 + i,
          length: 2,
          layer: 6,
          key: 'tls.ciphersuite',
        }),
      );
    }
    out.push(
      field({
        name: 'Cipher Suites',
        value: `${csLen / 2} offered: ${suites.slice(0, 3).join(', ')}${suites.length > 3 ? ', ...' : ''}`,
        offset: o,
        length: 2 + csLen,
        layer: 6,
        key: 'tls.ciphersuites',
        why: 'The order is the client\'s preference. Because different clients offer different suites in different orders, this list — hashed together with the extension list — is the JA3 fingerprint, which identifies the client software even inside an encrypted session.',
        children: suiteFields,
      }),
    );
    o += 2 + csLen;

    const compLen = b[o];
    out.push(
      field({
        name: 'Compression Methods',
        value: compLen === 1 && b[o + 1] === 0 ? 'null (no compression)' : `${compLen} methods`,
        offset: o,
        length: 1 + compLen,
        layer: 6,
        key: 'tls.compression',
        why: 'It must be null. TLS-level compression before encryption leaked plaintext through ciphertext length — the CRIME attack — so it was removed from TLS 1.3 entirely. This field survives only as a fossil.',
      }),
    );
    o += 1 + compLen;
  } else {
    const cs = readU16BE(b, o);
    summary.cipherSuite = CIPHER_SUITES[cs] ?? hex(cs, 4);
    out.push(
      field({
        name: 'Cipher Suite (selected)',
        value: `${hex(cs, 4)} (${CIPHER_SUITES[cs] ?? 'unknown'})`,
        offset: o,
        length: 2,
        layer: 6,
        key: 'tls.ciphersuite',
        why: 'The server has chosen one suite from the client\'s list. This single number fixes the key exchange, the authentication algorithm, the bulk cipher and the hash for the rest of the session — the entire representation of everything above.',
      }),
    );
    o += 2;
    out.push(
      field({
        name: 'Compression Method (selected)',
        value: b[o] === 0 ? 'null' : String(b[o]),
        offset: o,
        length: 1,
        layer: 6,
        key: 'tls.compression',
      }),
    );
    o += 1;
  }

  if (o + 2 > end) return out;
  const extTotal = readU16BE(b, o);
  const extStart = o + 2;
  const extEnd = Math.min(end, extStart + extTotal);
  const extFields: Field[] = [];
  let e = extStart;
  let guard = 0;

  while (e + 4 <= extEnd && guard++ < 64) {
    const extType = readU16BE(b, e);
    const extLen = readU16BE(b, e + 2);
    const dataStart = e + 4;
    const dataEnd = Math.min(extEnd, dataStart + extLen);
    const extName = EXTENSIONS[extType] ?? `extension ${extType}`;
    let value = `${extLen} bytes`;
    let why: string | undefined;
    let key: string | undefined;
    let layer: 5 | 6 | 7 = 6;

    switch (extType) {
      case 0: {
        // server_name: list length (2) + type (1) + name length (2) + name
        if (dataEnd - dataStart >= 5) {
          const nameLen = readU16BE(b, dataStart + 3);
          let host = '';
          for (let i = 0; i < nameLen && dataStart + 5 + i < dataEnd; i++) host += String.fromCharCode(b[dataStart + 5 + i]);
          summary.sni = host;
          value = host;
          key = 'tls.ext.sni';
          layer = 7;
          why = `The client is telling the server which hostname it wants — "${host}" — and it does so in clear text, before any encryption exists. This is what lets one IP serve many certificates, and it is also the single most useful field in an encrypted capture: it identifies the destination site even though everything else is opaque. Encrypted Client Hello (ECH) is the ongoing work to close this gap.`;
        }
        break;
      }
      case 16: {
        const protos: string[] = [];
        let p = dataStart + 2;
        while (p < dataEnd) {
          const len = b[p];
          let s = '';
          for (let i = 0; i < len && p + 1 + i < dataEnd; i++) s += String.fromCharCode(b[p + 1 + i]);
          if (s) protos.push(s);
          p += 1 + len;
        }
        summary.alpn = protos;
        value = protos.join(', ');
        key = 'tls.ext.alpn';
        layer = 7;
        why = `The client can speak ${protos.join(' or ')}. The server picks one, so the application protocol is settled before the first byte of Layer 7 data is sent — saving a whole round trip compared with negotiating afterwards.`;
        break;
      }
      case 43: {
        const versions: string[] = [];
        const listLen = b[dataStart];
        for (let i = 0; i + 1 < listLen && dataStart + 1 + i + 1 < dataEnd; i += 2) {
          const v = readU16BE(b, dataStart + 1 + i);
          versions.push(VERSIONS[v] ?? hex(v, 4));
        }
        if (versions.length === 0 && dataEnd - dataStart >= 2) {
          const v = readU16BE(b, dataStart);
          versions.push(VERSIONS[v] ?? hex(v, 4));
        }
        value = versions.join(', ');
        key = 'tls.ext.versions';
        summary.negotiatedVersion = versions[0];
        why = versions.includes('TLS 1.3')
          ? 'TLS 1.3 is offered here. Ignore the legacy version fields above — this extension is where the real version negotiation happens in every modern handshake.'
          : undefined;
        break;
      }
      case 51: {
        const entries: string[] = [];
        let p = isClient ? dataStart + 2 : dataStart;
        while (p + 4 <= dataEnd) {
          const group = readU16BE(b, p);
          const kLen = readU16BE(b, p + 2);
          entries.push(`${GROUPS[group] ?? hex(group, 4)} (${kLen} bytes)`);
          p += 4 + kLen;
          if (!isClient) break;
        }
        value = entries.join(', ');
        key = 'tls.ext.keyshare';
        why = 'The client is guessing which group the server will choose and sending its Diffie-Hellman public key immediately. If the guess is right — and it usually is — TLS 1.3 completes in one round trip instead of two.';
        break;
      }
      case 10: {
        const names: string[] = [];
        const listLen = readU16BE(b, dataStart);
        for (let i = 0; i + 1 < listLen && dataStart + 2 + i + 1 < dataEnd; i += 2) {
          const g = readU16BE(b, dataStart + 2 + i);
          names.push(GROUPS[g] ?? hex(g, 4));
        }
        value = names.join(', ');
        key = 'tls.ext.groups';
        break;
      }
      case 35:
        summary.ticketBytes = extLen;
        key = 'tls.ticket';
        layer = 5;
        value = extLen === 0 ? 'present, empty (client supports tickets)' : `${extLen}-byte ticket offered`;
        why = extLen === 0
          ? 'An empty session_ticket extension advertises support without offering one to resume.'
          : 'The client is presenting a ticket it was given earlier, asking the server to resume that session rather than build a new one.';
        break;
      default:
        value = extLen === 0 ? '(empty)' : hexPreview(b, dataStart, Math.min(extLen, 16), 16);
        break;
    }

    extFields.push(
      field({
        name: extName,
        value,
        offset: e,
        length: 4 + extLen,
        layer,
        key,
        whatText: key ? undefined : 'A TLS extension. Extensions are how TLS has evolved without changing the record format.',
        why,
      }),
    );
    e = dataStart + extLen;
  }

  out.push(
    field({
      name: `Extensions (${extFields.length})`,
      value: extFields.map((f) => f.name.replace(/ \(.*/, '')).join(', '),
      offset: o,
      length: 2 + extTotal,
      layer: 6,
      key: 'tls.extensions',
      children: extFields,
    }),
  );

  return out;
}
