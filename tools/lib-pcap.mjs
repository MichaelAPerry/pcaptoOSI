/**
 * Byte-level helpers for building the bundled teaching captures.
 *
 * These build genuine, standards-conformant frames — correct lengths, correct
 * Internet checksums, correct TCP sequence arithmetic — so the samples behave
 * exactly like real traffic in this tool, in Wireshark, or in tshark.
 */

export function bytes(...parts) {
  const flat = [];
  for (const part of parts) {
    if (typeof part === 'number') flat.push(part & 0xff);
    else if (typeof part === 'string') for (const c of Buffer.from(part, 'latin1')) flat.push(c);
    else for (const b of part) flat.push(b & 0xff);
  }
  return Buffer.from(flat);
}

export const u8 = (n) => Buffer.from([n & 0xff]);
export const u16 = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
export const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
export const u32 = (n) => Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);

export function mac(str) {
  return Buffer.from(str.split(':').map((p) => parseInt(p, 16)));
}

export function ip4(str) {
  return Buffer.from(str.split('.').map(Number));
}

export function ip6(str) {
  // Expand "::" then parse eight 16-bit groups.
  const [head, tail] = str.split('::');
  const headGroups = head ? head.split(':').filter(Boolean) : [];
  const tailGroups = tail ? tail.split(':').filter(Boolean) : [];
  const fill = 8 - headGroups.length - tailGroups.length;
  const groups = [...headGroups, ...Array(str.includes('::') ? fill : 0).fill('0'), ...tailGroups];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

/** RFC 1071 Internet checksum. */
export function checksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += (buf[i] << 8) | buf[i + 1];
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

export function ethernet(dst, src, etherType, payload, vlan) {
  const parts = [mac(dst), mac(src)];
  if (vlan !== undefined) {
    parts.push(u16(0x8100), u16(vlan));
  }
  parts.push(u16(etherType), payload);
  let frame = Buffer.concat(parts);
  // Real NICs pad short frames to the 60-byte minimum (64 with the FCS).
  if (frame.length < 60) frame = Buffer.concat([frame, Buffer.alloc(60 - frame.length)]);
  return frame;
}

export function ipv4({ src, dst, protocol, payload, ttl = 64, id = 0, df = true, dscp = 0, ecn = 0 }) {
  const totalLength = 20 + payload.length;
  const flagsFrag = (df ? 0x4000 : 0) | 0;
  const header = Buffer.concat([
    u8(0x45),
    u8((dscp << 2) | ecn),
    u16(totalLength),
    u16(id),
    u16(flagsFrag),
    u8(ttl),
    u8(protocol),
    u16(0),
    ip4(src),
    ip4(dst),
  ]);
  header.writeUInt16BE(checksum(header), 10);
  return Buffer.concat([header, payload]);
}

export function ipv6({ src, dst, nextHeader, payload, hopLimit = 64, trafficClass = 0, flowLabel = 0 }) {
  const first = (6 << 28) | (trafficClass << 20) | flowLabel;
  return Buffer.concat([u32(first >>> 0), u16(payload.length), u8(nextHeader), u8(hopLimit), ip6(src), ip6(dst), payload]);
}

function pseudoHeader4(src, dst, protocol, length) {
  return Buffer.concat([ip4(src), ip4(dst), u8(0), u8(protocol), u16(length)]);
}

function pseudoHeader6(src, dst, protocol, length) {
  return Buffer.concat([ip6(src), ip6(dst), u32(length), Buffer.alloc(3), u8(protocol)]);
}

export function udp({ src, dst, sport, dport, payload, v6 = false }) {
  const length = 8 + payload.length;
  const header = Buffer.concat([u16(sport), u16(dport), u16(length), u16(0)]);
  const body = Buffer.concat([header, payload]);
  const pseudo = v6 ? pseudoHeader6(src, dst, 17, length) : pseudoHeader4(src, dst, 17, length);
  let sum = checksum(Buffer.concat([pseudo, body]));
  if (sum === 0) sum = 0xffff;
  body.writeUInt16BE(sum, 6);
  return body;
}

export const TCP_FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20, ECE: 0x40, CWR: 0x80 };

export function tcp({ src, dst, sport, dport, seq, ack = 0, flags, window = 64240, payload = Buffer.alloc(0), options = Buffer.alloc(0), v6 = false }) {
  let opts = options;
  if (opts.length % 4 !== 0) opts = Buffer.concat([opts, Buffer.alloc(4 - (opts.length % 4))]);
  const dataOffset = (20 + opts.length) / 4;
  const header = Buffer.concat([
    u16(sport),
    u16(dport),
    u32(seq),
    u32(ack),
    u8(dataOffset << 4),
    u8(flags),
    u16(window),
    u16(0),
    u16(0),
    opts,
  ]);
  const body = Buffer.concat([header, payload]);
  const pseudo = v6 ? pseudoHeader6(src, dst, 6, body.length) : pseudoHeader4(src, dst, 6, body.length);
  body.writeUInt16BE(checksum(Buffer.concat([pseudo, body])), 16);
  return body;
}

export function tcpOptions(list) {
  const parts = [];
  for (const opt of list) {
    switch (opt.kind) {
      case 'mss':
        parts.push(bytes(2, 4, u16(opt.value)));
        break;
      case 'sackperm':
        parts.push(bytes(4, 2));
        break;
      case 'ts':
        parts.push(bytes(8, 10, u32(opt.value), u32(opt.echo ?? 0)));
        break;
      case 'wscale':
        parts.push(bytes(3, 3, opt.value));
        break;
      case 'nop':
        parts.push(bytes(1));
        break;
      default:
        throw new Error(`unknown tcp option ${opt.kind}`);
    }
  }
  let buf = Buffer.concat(parts);
  while (buf.length % 4 !== 0) buf = Buffer.concat([buf, Buffer.from([1])]); // pad with NOPs
  return buf;
}

export function icmpEcho({ type, id, seq, data }) {
  const header = Buffer.concat([u8(type), u8(0), u16(0), u16(id), u16(seq)]);
  const body = Buffer.concat([header, data]);
  body.writeUInt16BE(checksum(body), 2);
  return body;
}

export function icmp6Echo({ type, id, seq, data, src, dst }) {
  const header = Buffer.concat([u8(type), u8(0), u16(0), u16(id), u16(seq)]);
  const body = Buffer.concat([header, data]);
  const pseudo = pseudoHeader6(src, dst, 58, body.length);
  body.writeUInt16BE(checksum(Buffer.concat([pseudo, body])), 2);
  return body;
}

export function arp({ op, senderMac, senderIp, targetMac, targetIp }) {
  return Buffer.concat([
    u16(1),
    u16(0x0800),
    u8(6),
    u8(4),
    u16(op),
    mac(senderMac),
    ip4(senderIp),
    mac(targetMac),
    ip4(targetIp),
  ]);
}

/** Encode a DNS name as length-prefixed labels. */
export function dnsName(name) {
  if (name === '' || name === '.') return Buffer.from([0]);
  const parts = name.split('.').filter(Boolean);
  const out = [];
  for (const p of parts) {
    out.push(u8(p.length), Buffer.from(p, 'ascii'));
  }
  out.push(u8(0));
  return Buffer.concat(out);
}

/** A compression pointer to `offset` bytes from the start of the DNS message. */
export function dnsPointer(offset) {
  return u16(0xc000 | offset);
}

/* ------------------------------------------------------------- writers — */

export function writePcap(packets, { linkType = 1, snapLen = 262144, endian = 'little' } = {}) {
  const little = endian === 'little';
  const w32 = (n) => {
    const b = Buffer.alloc(4);
    if (little) b.writeUInt32LE(n >>> 0, 0);
    else b.writeUInt32BE(n >>> 0, 0);
    return b;
  };
  const w16 = (n) => {
    const b = Buffer.alloc(2);
    if (little) b.writeUInt16LE(n & 0xffff, 0);
    else b.writeUInt16BE(n & 0xffff, 0);
    return b;
  };

  const header = Buffer.concat([
    w32(0xa1b2c3d4),
    w16(2),
    w16(4),
    w32(0),
    w32(0),
    w32(snapLen),
    w32(linkType),
  ]);

  const records = packets.map((p) => {
    const sec = Math.floor(p.time);
    const usec = Math.round((p.time - sec) * 1e6);
    return Buffer.concat([w32(sec), w32(usec), w32(p.data.length), w32(p.origLength ?? p.data.length), p.data]);
  });
  return Buffer.concat([header, ...records]);
}

export function writePcapng(packets, { linkType = 1, snapLen = 262144, ifName = 'eth0', ifDescription = '', comment = '' } = {}) {
  const blocks = [];

  const shbOptions = comment
    ? Buffer.concat([u16(1), u16(comment.length), pad4(Buffer.from(comment, 'utf8')), u16(0), u16(0)])
    : Buffer.alloc(0);
  const shbBody = Buffer.concat([u32(0x1a2b3c4d), u16(1), u16(0), Buffer.alloc(8, 0xff), shbOptions]);
  blocks.push(block(0x0a0d0d0a, shbBody));

  const ifOptions = Buffer.concat([
    u16(2),
    u16(ifName.length),
    pad4(Buffer.from(ifName, 'utf8')),
    ...(ifDescription ? [u16(3), u16(ifDescription.length), pad4(Buffer.from(ifDescription, 'utf8'))] : []),
    u16(9),
    u16(1),
    pad4(Buffer.from([6])), // if_tsresol: 10^-6 seconds
    u16(0),
    u16(0),
  ]);
  blocks.push(block(0x00000001, Buffer.concat([u16(linkType), u16(0), u32(snapLen), ifOptions])));

  for (const p of packets) {
    const ticks = BigInt(Math.round(p.time * 1e6));
    const high = Number(ticks >> 32n);
    const low = Number(ticks & 0xffffffffn);
    const body = Buffer.concat([
      u32(0),
      u32(high),
      u32(low),
      u32(p.data.length),
      u32(p.origLength ?? p.data.length),
      pad4(p.data),
    ]);
    blocks.push(block(0x00000006, body));
  }

  return Buffer.concat(blocks);
}

function pad4(buf) {
  const rem = buf.length % 4;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(4 - rem)]);
}

function block(type, body) {
  const total = 12 + body.length;
  return Buffer.concat([u32(type), u32(total), body, u32(total)]);
}
