/** IPv4 header dissection, including options, fragmentation and checksum verification. */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { bitMaskString, formatIPv4, hex, hexPreview, internetChecksum, readU16BE } from '../bytes';
import { dissectTcp } from './tcp';
import { dissectUdp } from './udp';
import { dissectIcmp } from './icmp';
import { addUnknownPayload } from './ethernet';

export const IP_PROTOCOLS: Record<number, string> = {
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6 encapsulation',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  89: 'OSPF',
  103: 'PIM',
  112: 'VRRP',
  132: 'SCTP',
};

const DSCP_NAMES: Record<number, string> = {
  0: 'CS0 / Default (best effort)',
  8: 'CS1 (scavenger)',
  10: 'AF11',
  16: 'CS2',
  18: 'AF21',
  24: 'CS3 (signalling)',
  26: 'AF31',
  32: 'CS4',
  34: 'AF41 (interactive video)',
  40: 'CS5',
  46: 'EF (expedited forwarding, voice)',
  48: 'CS6 (network control)',
  56: 'CS7',
};

const ECN_NAMES: Record<number, string> = {
  0: 'Not ECN-Capable Transport',
  1: 'ECT(1)',
  2: 'ECT(0)',
  3: 'CE — congestion experienced',
};

/** Best-effort guess at the originating OS from the initial TTL. */
export function ttlHint(ttl: number): string {
  const candidates = [
    { initial: 32, os: 'older Windows (95/98/ME)' },
    { initial: 64, os: 'Linux, macOS, Android, iOS and most BSDs' },
    { initial: 128, os: 'modern Windows' },
    { initial: 255, os: 'network equipment (Cisco IOS, Solaris) and many routing protocols' },
  ];
  const match = candidates.find((c) => ttl <= c.initial && c.initial - ttl < 32);
  if (!match) return `A TTL of ${ttl} does not sit just below any of the common initial values.`;
  const hops = match.initial - ttl;
  const fingerprint =
    'This is the basis of passive OS fingerprinting — and the reason traceroute works: send a packet with TTL=1, ' +
    'and the first router returns ICMP Time Exceeded, revealing itself.';

  if (hops === 0) {
    return (
      `Common stacks start at 32, 64, 128 or 255. ${ttl} is exactly one of them, so this packet has not been ` +
      `decremented by any router yet: it was captured on the sending host itself, or somewhere on the same segment. ` +
      `An initial TTL of ${match.initial} points at ${match.os}. ${fingerprint}`
    );
  }
  return (
    `Common stacks start at 32, 64, 128 or 255. ${ttl} is ${hops} below ${match.initial}, which suggests the sender was ` +
    `${match.os} and that the packet crossed ${hops} router${hops === 1 ? '' : 's'} to reach the capture point. ` +
    fingerprint
  );
}

/** Classify an IPv4 address the way an analyst would at a glance. */
export function ipv4Nature(addr: string): string {
  const [a, b] = addr.split('.').map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return 'RFC 1918 private address — it is not routable on the public Internet, so something is doing NAT if this conversation leaves the site.';
  }
  if (a === 127) return 'Loopback: the packet never left the host.';
  if (a === 169 && b === 254) return 'APIPA / link-local: the host failed to get a DHCP lease and picked this address itself.';
  if (a >= 224 && a <= 239) return 'Multicast group address — delivered to every host that has joined the group.';
  if (addr === '255.255.255.255') return 'Limited broadcast: every host on the local segment, never forwarded by a router.';
  if (addr === '0.0.0.0') return '"This host, this network" — used before an address has been assigned, as in a DHCP Discover.';
  if (a >= 240) return 'Reserved (class E) address space.';
  if (a === 100 && b >= 64 && b <= 127) return 'RFC 6598 carrier-grade NAT space.';
  return 'Globally routable public address.';
}

export function dissectIPv4(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 20)) {
    ctx.truncated('IPv4', offset, 20);
    addUnknownPayload(ctx, offset, 'IPv4');
    return;
  }

  const versionIhl = b[offset];
  const version = versionIhl >> 4;
  const ihl = versionIhl & 0x0f;
  const headerLength = ihl * 4;
  const tosByte = b[offset + 1];
  const dscp = tosByte >> 2;
  const ecn = tosByte & 0x03;
  const totalLength = readU16BE(b, offset + 2);
  const identification = readU16BE(b, offset + 4);
  const flagsFrag = readU16BE(b, offset + 6);
  const reservedFlag = (flagsFrag >> 15) & 1;
  const dontFragment = (flagsFrag >> 14) & 1;
  const moreFragments = (flagsFrag >> 13) & 1;
  const fragOffset = flagsFrag & 0x1fff;
  const ttl = b[offset + 8];
  const protocol = b[offset + 9];
  const checksum = readU16BE(b, offset + 10);
  const src = formatIPv4(b, offset + 12);
  const dst = formatIPv4(b, offset + 16);

  ctx.term(src, dst, 'ip', 'ipv4', IP_PROTOCOLS[protocol]?.toLowerCase());

  if (version !== 4) ctx.warn(`IPv4 dissector invoked but the version nibble is ${version}.`);
  if (ihl < 5) ctx.warn(`Invalid IPv4 header length (IHL=${ihl}); the minimum is 5.`);

  const headerBytes = b.subarray(offset, offset + Math.max(20, headerLength));
  const computed = internetChecksum([headerBytes], { start: 10, length: 2 });
  const checksumOk = computed === checksum;

  const protoName = IP_PROTOCOLS[protocol] ?? `protocol ${protocol}`;

  const fields: Field[] = [
    field({
      name: 'Version',
      value: String(version),
      offset,
      length: 1,
      bits: { offset: 0, length: 4 },
      layer: 3,
      key: 'ip.version',
      why: `The first nibble is ${version}, so every dissector downstream knows to read an IPv4 header. ${bitMaskString(versionIhl, 8, 0, 4)}`,
    }),
    field({
      name: 'Header Length (IHL)',
      value: `${ihl} words = ${headerLength} bytes`,
      offset,
      length: 1,
      bits: { offset: 4, length: 4 },
      layer: 3,
      key: 'ip.ihl',
      why:
        ihl === 5
          ? 'IHL 5 is the minimum: a plain 20-byte header with no options, which is what virtually all Internet traffic uses.'
          : `IHL ${ihl} means ${headerLength - 20} bytes of IPv4 options follow the fixed header.`,
    }),
    field({
      name: 'DSCP',
      value: `${dscp} (${DSCP_NAMES[dscp] ?? 'unassigned'})`,
      offset: offset + 1,
      length: 1,
      bits: { offset: 0, length: 6 },
      layer: 3,
      key: 'ip.dscp',
      why:
        dscp === 0
          ? 'Best effort: no special queuing treatment is requested, which is normal for bulk traffic.'
          : `A non-zero DSCP asks routers for differentiated treatment. ${DSCP_NAMES[dscp] ?? ''} Note that QoS marks are only honoured inside a trust boundary — the public Internet usually rewrites or ignores them.`,
    }),
    field({
      name: 'ECN',
      value: `${ecn} (${ECN_NAMES[ecn]})`,
      offset: offset + 1,
      length: 1,
      bits: { offset: 6, length: 2 },
      layer: 3,
      key: 'ip.ecn',
      why:
        ecn === 3
          ? 'CE is set: a router on the path is congested and marked this packet instead of dropping it. TCP should react by halving its congestion window.'
          : ecn === 0
            ? 'The endpoints did not negotiate ECN, so routers signal congestion the old way — by dropping packets.'
            : 'The endpoints negotiated ECN, so a congested router can mark this packet rather than drop it.',
    }),
    field({
      name: 'Total Length',
      value: `${totalLength} bytes`,
      offset: offset + 2,
      length: 2,
      layer: 3,
      key: 'ip.totallen',
      why: `Header (${headerLength} bytes) plus payload (${totalLength - headerLength} bytes). Compare it with the frame length: any difference is Ethernet padding, not data.`,
      note: totalLength < headerLength ? 'error' : undefined,
    }),
    field({
      name: 'Identification',
      value: `${identification} (${hex(identification, 4)})`,
      offset: offset + 4,
      length: 2,
      layer: 3,
      key: 'ip.id',
      why:
        identification === 0
          ? 'An ID of zero is normal for packets with DF set that will never be fragmented — Linux does this deliberately.'
          : 'All fragments of one datagram share this value. It is also the field an idle scan abuses, because predictable IDs leak how much traffic a host is sending.',
    }),
    field({
      name: 'Flags',
      value: `${dontFragment ? 'DF' : ''}${dontFragment && moreFragments ? ', ' : ''}${moreFragments ? 'MF' : ''}` || 'none set',
      offset: offset + 6,
      length: 1,
      bits: { offset: 0, length: 3 },
      layer: 3,
      key: 'ip.flags',
      children: [
        field({
          name: 'Reserved bit',
          value: String(reservedFlag),
          offset: offset + 6,
          length: 1,
          bits: { offset: 0, length: 1 },
          layer: 3,
          whatText: 'Must be zero. Sometimes repurposed as an "evil bit" joke (RFC 3514).',
        }),
        field({
          name: "Don't Fragment (DF)",
          value: dontFragment ? '1 = set' : '0 = not set',
          offset: offset + 6,
          length: 1,
          bits: { offset: 1, length: 1 },
          layer: 3,
          key: 'ip.flag.df',
          why: dontFragment
            ? 'DF is set, so if this packet is too big for a link on the path the router must drop it and send back ICMP "Fragmentation Needed". If a firewall eats that ICMP, you get a PMTU black hole: small packets work, large ones vanish.'
            : 'DF is clear, so a router may fragment this packet if it hits a smaller MTU.',
        }),
        field({
          name: 'More Fragments (MF)',
          value: moreFragments ? '1 = set' : '0 = not set',
          offset: offset + 6,
          length: 1,
          bits: { offset: 2, length: 1 },
          layer: 3,
          key: 'ip.flag.mf',
          why: moreFragments ? 'More fragments follow: this is not the last piece of the datagram.' : undefined,
        }),
      ],
    }),
    field({
      name: 'Fragment Offset',
      value: `${fragOffset} (${fragOffset * 8} bytes)`,
      offset: offset + 6,
      length: 2,
      bits: { offset: 3, length: 13 },
      layer: 3,
      key: 'ip.fragoffset',
      why:
        fragOffset === 0 && !moreFragments
          ? 'Offset 0 with MF clear means this is a complete, unfragmented datagram.'
          : `This fragment starts ${fragOffset * 8} bytes into the original datagram. Only the first fragment carries the transport header, which is why fragmented traffic defeats naive port-based filtering.`,
    }),
    field({
      name: 'Time to Live',
      value: String(ttl),
      offset: offset + 8,
      length: 1,
      layer: 3,
      key: 'ip.ttl',
      why: ttlHint(ttl),
      note: ttl <= 1 ? 'warn' : undefined,
    }),
    field({
      name: 'Protocol',
      value: `${protocol} (${protoName})`,
      offset: offset + 9,
      length: 1,
      layer: 3,
      key: 'ip.proto',
      why: `This is the hand-off from Layer 3 to Layer 4: the next ${totalLength - headerLength} bytes are a ${protoName} header and its payload.`,
    }),
    field({
      name: 'Header Checksum',
      value: `${hex(checksum, 4)} ${checksumOk ? '(valid)' : `(INVALID — computed ${hex(computed, 4)})`}`,
      offset: offset + 10,
      length: 2,
      layer: 3,
      key: 'ip.checksum',
      why: checksumOk
        ? 'Verified against the captured header bytes. Every router recalculates this because it decrements the TTL.'
        : 'The checksum does not match the header as captured. On a capture taken on the sending host this usually means checksum offload — the NIC fills the field in after the packet is handed to the driver — rather than genuine corruption.',
      note: checksumOk ? undefined : 'warn',
    }),
    field({
      name: 'Source Address',
      value: src,
      offset: offset + 12,
      length: 4,
      layer: 3,
      key: 'ip.src',
      why: ipv4Nature(src),
    }),
    field({
      name: 'Destination Address',
      value: dst,
      offset: offset + 16,
      length: 4,
      layer: 3,
      key: 'ip.dst',
      why: ipv4Nature(dst),
    }),
  ];

  if (headerLength > 20 && ctx.has(offset + 20, headerLength - 20)) {
    fields.push(
      field({
        name: 'Options',
        value: hexPreview(b, offset + 20, headerLength - 20),
        offset: offset + 20,
        length: headerLength - 20,
        layer: 3,
        key: 'ip.options',
        children: parseIpv4Options(ctx, offset + 20, headerLength - 20),
      }),
    );
  }

  ctx.add({
    id: 'ipv4',
    name: 'Internet Protocol Version 4',
    abbr: 'IPv4',
    layer: 3,
    summary: `${src} -> ${dst}, ${protoName}, TTL ${ttl}`,
    offset,
    length: headerLength,
    fields,
    payload: {
      offset: offset + headerLength,
      length: Math.max(0, Math.min(totalLength - headerLength, b.length - offset - headerLength)),
    },
  });

  ctx.source = src;
  ctx.destination = dst;
  ctx.ipSrcBytes = b.subarray(offset + 12, offset + 16);
  ctx.ipDstBytes = b.subarray(offset + 16, offset + 20);
  ctx.ipVersion = 4;
  ctx.ipProtocol = protocol;
  ctx.transportEnd = Math.min(b.length, offset + Math.max(headerLength, totalLength));
  ctx.info = `${protoName} ${src} -> ${dst}`;

  const payloadStart = offset + headerLength;
  // Only the first fragment carries a readable transport header.
  if (fragOffset > 0) {
    ctx.warn(`This is IPv4 fragment ${fragOffset * 8} of datagram ID ${identification}; the transport header is in the first fragment.`);
    ctx.info = `Fragmented IP protocol=${protoName} id=${hex(identification, 4)} offset=${fragOffset * 8}`;
    addUnknownPayload(ctx, payloadStart, 'IPv4 fragment');
    return;
  }

  dispatchTransport(ctx, protocol, payloadStart, protoName);
}

export function dispatchTransport(
  ctx: DissectContext,
  protocol: number,
  offset: number,
  protoName: string,
): void {
  switch (protocol) {
    case 6:
      dissectTcp(ctx, offset);
      break;
    case 17:
      dissectUdp(ctx, offset);
      break;
    case 1:
      dissectIcmp(ctx, offset, false);
      break;
    case 58:
      dissectIcmp(ctx, offset, true);
      break;
    default:
      addUnknownPayload(ctx, offset, protoName);
      break;
  }
}

const IPV4_OPTIONS: Record<number, string> = {
  0: 'End of Option List',
  1: 'No Operation',
  7: 'Record Route',
  68: 'Timestamp',
  130: 'Security',
  131: 'Loose Source Route',
  136: 'Stream ID',
  137: 'Strict Source Route',
  148: 'Router Alert',
};

function parseIpv4Options(ctx: DissectContext, offset: number, length: number): Field[] {
  const out: Field[] = [];
  const b = ctx.bytes;
  let o = offset;
  const end = offset + length;
  while (o < end) {
    const type = b[o];
    if (type === 0) {
      out.push(field({ name: 'End of Option List', value: '0', offset: o, length: 1, layer: 3, whatText: IPV4_OPTIONS[0] }));
      break;
    }
    if (type === 1) {
      out.push(field({ name: 'No Operation (padding)', value: '1', offset: o, length: 1, layer: 3, whatText: IPV4_OPTIONS[1] }));
      o += 1;
      continue;
    }
    const len = b[o + 1] ?? 0;
    if (len < 2 || o + len > end) {
      ctx.warn('Malformed IPv4 option length; stopping option parsing.');
      break;
    }
    out.push(
      field({
        name: IPV4_OPTIONS[type] ?? `Option type ${type}`,
        value: hexPreview(b, o, len),
        offset: o,
        length: len,
        layer: 3,
        whatText:
          'An IPv4 header option. Options are rare on the modern Internet because they force routers onto a slow software path, and many networks drop packets that carry them.',
      }),
    );
    o += len;
  }
  return out;
}
