/**
 * DNS dissection (also used for mDNS and DNS over TCP).
 *
 * Includes full name decompression, which is worth showing students: it is the
 * reason a DNS response can pack a dozen records into a single small datagram.
 */

import type { Field, ProtocolLayer } from '../types';
import { DissectContext, field } from './context';
import { formatIPv4, formatIPv6, hex, hexPreview, readU16BE, readU32BE } from '../bytes';

const TYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  35: 'NAPTR',
  41: 'OPT (EDNS0)',
  43: 'DS',
  46: 'RRSIG',
  47: 'NSEC',
  48: 'DNSKEY',
  52: 'TLSA',
  64: 'SVCB',
  65: 'HTTPS',
  99: 'SPF',
  255: 'ANY',
  257: 'CAA',
};

const RCODES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN — the name does not exist',
  4: 'NOTIMP',
  5: 'REFUSED',
};

const OPCODES: Record<number, string> = { 0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE' };

interface NameResult {
  name: string;
  /** Bytes consumed in the message at the original position. */
  consumed: number;
  compressed: boolean;
}

/**
 * Decode a DNS name starting at `pos`, following compression pointers.
 * `base` is the offset of the first byte of the DNS message, because pointers
 * are relative to the start of the message, not the start of the packet.
 */
export function readDnsName(b: Uint8Array, base: number, pos: number, limit: number): NameResult {
  const labels: string[] = [];
  let consumed = 0;
  let jumped = false;
  let compressed = false;
  let cursor = pos;
  let guard = 0;

  while (cursor < limit && guard++ < 128) {
    const len = b[cursor];
    if (len === 0) {
      if (!jumped) consumed += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer: the low 14 bits are an offset into the message.
      if (cursor + 1 >= limit) break;
      const pointer = ((len & 0x3f) << 8) | b[cursor + 1];
      if (!jumped) {
        consumed += 2;
        jumped = true;
      }
      compressed = true;
      cursor = base + pointer;
      continue;
    }
    if (cursor + 1 + len > limit) break;
    let label = '';
    for (let i = 0; i < len; i++) label += String.fromCharCode(b[cursor + 1 + i]);
    labels.push(label);
    cursor += 1 + len;
    if (!jumped) consumed += 1 + len;
  }

  return { name: labels.join('.') || '<root>', consumed: Math.max(consumed, 1), compressed };
}

function rdataText(b: Uint8Array, base: number, offset: number, length: number, type: number, limit: number): string {
  switch (type) {
    case 1:
      return length >= 4 ? formatIPv4(b, offset) : '(malformed A record)';
    case 28:
      return length >= 16 ? formatIPv6(b, offset) : '(malformed AAAA record)';
    case 2:
    case 5:
    case 12:
      return readDnsName(b, base, offset, limit).name;
    case 15: {
      const pref = readU16BE(b, offset);
      return `preference ${pref}, exchange ${readDnsName(b, base, offset + 2, limit).name}`;
    }
    case 16: {
      const strLen = b[offset];
      let s = '';
      for (let i = 0; i < strLen && offset + 1 + i < limit; i++) s += String.fromCharCode(b[offset + 1 + i]);
      return `"${s}"`;
    }
    case 6: {
      const mname = readDnsName(b, base, offset, limit);
      const rname = readDnsName(b, base, offset + mname.consumed, limit);
      return `${mname.name} ${rname.name}`;
    }
    case 33: {
      if (length < 7) return '(malformed SRV)';
      const priority = readU16BE(b, offset);
      const weight = readU16BE(b, offset + 2);
      const port = readU16BE(b, offset + 4);
      return `priority ${priority} weight ${weight} port ${port} target ${readDnsName(b, base, offset + 6, limit).name}`;
    }
    default:
      return hexPreview(b, offset, length);
  }
}

export function dissectDns(ctx: DissectContext, offset: number, length: number, overTcp: boolean, label = 'DNS'): void {
  const b = ctx.bytes;
  const base = offset;
  const limit = Math.min(b.length, offset + length);
  if (limit - offset < 12) {
    ctx.warn('DNS message is shorter than the 12-byte header.');
    return;
  }

  const txid = readU16BE(b, offset);
  const flags = readU16BE(b, offset + 2);
  const qdCount = readU16BE(b, offset + 4);
  const anCount = readU16BE(b, offset + 6);
  const nsCount = readU16BE(b, offset + 8);
  const arCount = readU16BE(b, offset + 10);

  const qr = (flags >> 15) & 1;
  const opcode = (flags >> 11) & 0x0f;
  const aa = (flags >> 10) & 1;
  const tc = (flags >> 9) & 1;
  const rd = (flags >> 8) & 1;
  const ra = (flags >> 7) & 1;
  const rcode = flags & 0x0f;

  ctx.term('dns', qr ? 'response' : 'query');

  const fields: Field[] = [
    field({
      name: 'Transaction ID',
      value: hex(txid, 4),
      offset,
      length: 2,
      layer: 7,
      key: 'dns.txid',
      why: 'The resolver will only accept a response whose transaction ID, source port, question and address all match its outstanding query. Because that is only about 32 bits of entropy, forging responses (cache poisoning) is a real attack — which is what source-port randomisation and DNSSEC exist to counter.',
    }),
    field({
      name: 'Flags',
      value: `${hex(flags, 4)} (${qr ? 'response' : 'query'}${aa ? ', authoritative' : ''}${tc ? ', truncated' : ''}${rd ? ', recursion desired' : ''}${ra ? ', recursion available' : ''}, ${RCODES[rcode] ?? `rcode ${rcode}`})`,
      offset: offset + 2,
      length: 2,
      layer: 7,
      key: 'dns.flags',
      children: [
        field({ name: 'QR', value: qr ? '1 = response' : '0 = query', offset: offset + 2, length: 2, bits: { offset: 0, length: 1 }, layer: 7, key: 'dns.flag.qr' }),
        field({ name: 'Opcode', value: `${opcode} (${OPCODES[opcode] ?? 'reserved'})`, offset: offset + 2, length: 2, bits: { offset: 1, length: 4 }, layer: 7, key: 'dns.flag.opcode' }),
        field({
          name: 'Authoritative Answer',
          value: String(aa),
          offset: offset + 2,
          length: 2,
          bits: { offset: 5, length: 1 },
          layer: 7,
          key: 'dns.flag.aa',
          why: aa ? 'This answer came straight from a server that is authoritative for the zone, not from a cache.' : undefined,
        }),
        field({
          name: 'Truncated',
          value: String(tc),
          offset: offset + 2,
          length: 2,
          bits: { offset: 6, length: 1 },
          layer: 7,
          key: 'dns.flag.tc',
          why: tc ? 'The answer did not fit in the datagram. The client must now retry the whole query over TCP — a rare case where one exchange changes transport protocol mid-conversation.' : undefined,
          note: tc ? 'warn' : undefined,
        }),
        field({ name: 'Recursion Desired', value: String(rd), offset: offset + 2, length: 2, bits: { offset: 7, length: 1 }, layer: 7, key: 'dns.flag.rd' }),
        field({ name: 'Recursion Available', value: String(ra), offset: offset + 2, length: 2, bits: { offset: 8, length: 1 }, layer: 7, key: 'dns.flag.ra' }),
        field({
          name: 'Response Code',
          value: `${rcode} (${RCODES[rcode] ?? 'reserved'})`,
          offset: offset + 2,
          length: 2,
          bits: { offset: 12, length: 4 },
          layer: 7,
          key: 'dns.flag.rcode',
          note: rcode !== 0 ? 'warn' : undefined,
        }),
      ],
    }),
    field({
      name: 'Section counts',
      value: `${qdCount} question, ${anCount} answer, ${nsCount} authority, ${arCount} additional`,
      offset: offset + 4,
      length: 8,
      layer: 7,
      key: 'dns.counts',
    }),
  ];

  let cursor = offset + 12;
  const questionNames: string[] = [];

  for (let i = 0; i < qdCount && cursor < limit; i++) {
    const nameRes = readDnsName(b, base, cursor, limit);
    const nameLen = nameRes.consumed;
    if (cursor + nameLen + 4 > limit) break;
    const qtype = readU16BE(b, cursor + nameLen);
    const qclass = readU16BE(b, cursor + nameLen + 2);
    questionNames.push(`${TYPES[qtype] ?? qtype} ${nameRes.name}`);
    ctx.term(nameRes.name, TYPES[qtype]?.toLowerCase());

    fields.push(
      field({
        name: `Question ${i + 1}`,
        value: `${nameRes.name}, type ${TYPES[qtype] ?? qtype}, class ${qclass === 1 ? 'IN' : qclass}`,
        offset: cursor,
        length: nameLen + 4,
        layer: 7,
        whatText: 'One question: the name, the record type wanted, and the class.',
        children: [
          field({
            name: 'Name',
            value: nameRes.name,
            offset: cursor,
            length: nameLen,
            layer: 7,
            key: 'dns.qname',
            why: `Encoded as length-prefixed labels: ${nameRes.name.split('.').map((l) => `${l.length}"${l}"`).join(' ')} followed by a terminating zero byte. There are no dots on the wire — the dots are a display convention.`,
          }),
          field({ name: 'Type', value: `${qtype} (${TYPES[qtype] ?? 'unknown'})`, offset: cursor + nameLen, length: 2, layer: 7, key: 'dns.qtype' }),
          field({ name: 'Class', value: `${qclass}${qclass === 1 ? ' (IN)' : ''}`, offset: cursor + nameLen + 2, length: 2, layer: 7, key: 'dns.qclass' }),
        ],
      }),
    );
    cursor += nameLen + 4;
  }

  const answers: string[] = [];
  const sections: Array<[string, number]> = [
    ['Answer', anCount],
    ['Authority', nsCount],
    ['Additional', arCount],
  ];

  for (const [sectionName, count] of sections) {
    for (let i = 0; i < count && cursor < limit; i++) {
      const nameRes = readDnsName(b, base, cursor, limit);
      const nameLen = nameRes.consumed;
      if (cursor + nameLen + 10 > limit) break;
      const type = readU16BE(b, cursor + nameLen);
      const klass = readU16BE(b, cursor + nameLen + 2);
      const ttl = readU32BE(b, cursor + nameLen + 4);
      const rdLength = readU16BE(b, cursor + nameLen + 8);
      const rdOffset = cursor + nameLen + 10;
      if (rdOffset + rdLength > limit) break;
      const value = rdataText(b, base, rdOffset, rdLength, type, limit);
      if (sectionName === 'Answer') answers.push(`${TYPES[type] ?? type} ${value}`);
      ctx.term(nameRes.name, value);

      fields.push(
        field({
          name: `${sectionName} record ${i + 1}`,
          value: `${nameRes.name} ${TYPES[type] ?? type} ${value}`,
          offset: cursor,
          length: nameLen + 10 + rdLength,
          layer: 7,
          key: 'dns.rr',
          children: [
            field({
              name: 'Name',
              value: nameRes.name,
              offset: cursor,
              length: nameLen,
              layer: 7,
              key: nameRes.compressed ? 'dns.compression' : 'dns.qname',
              why: nameRes.compressed
                ? 'This name is stored as a two-byte pointer back to where it already appeared in the message. Highlight it in the hex pane: the two bytes begin with the bits 11, and the remaining 14 bits are an offset from the first byte of the DNS header.'
                : undefined,
            }),
            field({ name: 'Type', value: `${type} (${TYPES[type] ?? 'unknown'})`, offset: cursor + nameLen, length: 2, layer: 7, key: 'dns.qtype' }),
            field({ name: 'Class', value: `${klass}${klass === 1 ? ' (IN)' : ''}`, offset: cursor + nameLen + 2, length: 2, layer: 7, key: 'dns.qclass' }),
            field({
              name: 'Time to live',
              value: `${ttl} seconds`,
              offset: cursor + nameLen + 4,
              length: 4,
              layer: 7,
              key: 'dns.ttl',
              why: `Any resolver may reuse this answer for ${ttl} seconds (${(ttl / 60).toFixed(1)} minutes) without asking again. Note this is a DNS TTL measured in seconds — completely unrelated to the IP header's TTL, which counts router hops.`,
            }),
            field({ name: 'Data length', value: `${rdLength} bytes`, offset: cursor + nameLen + 8, length: 2, layer: 7, whatText: 'How many bytes of record-specific data follow.' }),
            field({ name: 'Record data', value, offset: rdOffset, length: rdLength, layer: 7, key: 'dns.rdata' }),
          ],
        }),
      );
      cursor += nameLen + 10 + rdLength;
    }
  }

  const summary = qr
    ? `Response ${hex(txid, 4)}: ${answers.length ? answers.join('; ') : RCODES[rcode] ?? 'no answers'}`
    : `Query ${hex(txid, 4)}: ${questionNames.join('; ')}`;

  const layer: ProtocolLayer = {
    id: 'dns',
    name: label === 'mDNS' ? 'Multicast DNS' : 'Domain Name System',
    abbr: label,
    layer: 7,
    summary,
    offset,
    length: Math.min(cursor, limit) - offset,
    fields,
  };
  ctx.add(layer);

  ctx.info = qr
    ? `Standard query response ${hex(txid, 4)} ${questionNames.join(' ')}${answers.length ? ' ' + answers.join(' ') : ` ${RCODES[rcode] ?? ''}`}`
    : `Standard query ${hex(txid, 4)} ${questionNames.join(' ')}`;

  // Layer 6: DNS defines its own binary wire format rather than using ASCII.
  ctx.add({
    id: 'dns-presentation',
    name: 'Presentation layer (DNS wire format)',
    abbr: 'DNS',
    layer: 6,
    virtual: true,
    summary: 'Binary, length-prefixed labels with pointer compression',
    offset,
    length: 0,
    fields: [
      field({
        name: 'Encoding',
        value: 'DNS binary wire format (RFC 1035)',
        offset,
        length: 12,
        layer: 6,
        synthetic: true,
        key: 'presentation.model',
        why: 'DNS does its own presentation-layer work: names are length-prefixed label sequences, integers are big-endian, and repeated names are replaced by 2-byte back-pointers. Nothing here is human-readable text, which is why you need a dissector rather than just reading the ASCII column.',
      }),
      field({
        name: 'Name compression in use',
        value: fields.some((f) => f.children?.some((c) => c.what.includes('pointer'))) ? 'yes' : 'no',
        offset,
        length: 0,
        layer: 6,
        synthetic: true,
        key: 'dns.compression',
      }),
    ],
  });

  // Layer 5: the transaction ID is the only session state DNS has over UDP.
  ctx.add({
    id: 'dns-session',
    name: overTcp ? 'Session layer (TCP connection + DNS transaction ID)' : 'Session layer (DNS transaction ID only)',
    abbr: 'DNS',
    layer: 5,
    virtual: true,
    summary: `Transaction ID ${hex(txid, 4)} correlates this message with its pair`,
    offset,
    length: 0,
    fields: [
      field({
        name: 'Transaction correlation',
        value: hex(txid, 4),
        offset,
        length: 2,
        layer: 5,
        key: 'dns.txid',
        why: overTcp
          ? 'Over TCP the connection itself provides ordering and reliability, so the transaction ID is only needed to match queries pipelined on the same connection.'
          : 'Over UDP there is no connection at all. This 16-bit number, plus the client\'s randomised source port, is the entire "session" — it is what a response must match to be believed.',
      }),
    ],
  });
}
