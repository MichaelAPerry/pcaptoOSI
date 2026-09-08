/** IPv6 header dissection, including the extension-header chain. */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { formatIPv6, hex, hexPreview, readU16BE } from '../bytes';
import { IP_PROTOCOLS, dispatchTransport } from './ipv4';
import { addUnknownPayload } from './ethernet';

const EXTENSION_HEADERS: Record<number, string> = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  51: 'Authentication Header',
  60: 'Destination Options',
  135: 'Mobility',
};

export function ipv6Nature(addr: string): string {
  const a = addr.toLowerCase();
  if (a === '::1') return 'Loopback — the packet never left the host.';
  if (a === '::') return 'The unspecified address, used before an address has been configured (e.g. in duplicate address detection).';
  if (a.startsWith('fe80')) return 'Link-local address. Every IPv6 interface has one; it is never routed off the link, and it is what Neighbour Discovery and routing protocols talk over.';
  if (a.startsWith('ff')) return 'Multicast. ff02::1 is all-nodes, ff02::2 is all-routers, and ff02::1:ff.. are the solicited-node groups that replace ARP broadcast.';
  if (a.startsWith('fc') || a.startsWith('fd')) return 'Unique Local Address (RFC 4193) — the IPv6 equivalent of RFC 1918 private space.';
  if (a.startsWith('2') || a.startsWith('3')) return 'Global unicast address, routable on the public IPv6 Internet.';
  return 'Address outside the commonly used IPv6 ranges.';
}

export function dissectIPv6(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 40)) {
    ctx.truncated('IPv6', offset, 40);
    addUnknownPayload(ctx, offset, 'IPv6');
    return;
  }

  const first4 = (b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3];
  const version = (b[offset] >> 4) & 0x0f;
  const trafficClass = ((b[offset] & 0x0f) << 4) | ((b[offset + 1] >> 4) & 0x0f);
  const flowLabel = first4 & 0xfffff;
  const payloadLength = readU16BE(b, offset + 4);
  const nextHeader = b[offset + 6];
  const hopLimit = b[offset + 7];
  const src = formatIPv6(b, offset + 8);
  const dst = formatIPv6(b, offset + 24);

  ctx.term(src, dst, 'ip', 'ipv6', IP_PROTOCOLS[nextHeader]?.toLowerCase());

  const nextName = IP_PROTOCOLS[nextHeader] ?? EXTENSION_HEADERS[nextHeader] ?? `protocol ${nextHeader}`;

  const fields: Field[] = [
    field({
      name: 'Version',
      value: String(version),
      offset,
      length: 1,
      bits: { offset: 0, length: 4 },
      layer: 3,
      key: 'ip6.version',
    }),
    field({
      name: 'Traffic Class',
      value: `${hex(trafficClass, 2)} (DSCP ${trafficClass >> 2}, ECN ${trafficClass & 3})`,
      offset,
      length: 2,
      bits: { offset: 4, length: 8 },
      layer: 3,
      key: 'ip6.tclass',
    }),
    field({
      name: 'Flow Label',
      value: hex(flowLabel, 5),
      offset: offset + 1,
      length: 3,
      bits: { offset: 4, length: 20 },
      layer: 3,
      key: 'ip6.flow',
      why:
        flowLabel === 0
          ? 'A zero flow label means the sender did not classify this packet into a flow, so routers fall back to hashing the addresses and ports.'
          : 'A non-zero flow label lets routers keep all packets of this flow on the same path without parsing the transport header — important when extension headers or encryption hide it.',
    }),
    field({
      name: 'Payload Length',
      value: `${payloadLength} bytes`,
      offset: offset + 4,
      length: 2,
      layer: 3,
      key: 'ip6.plen',
      why: 'Unlike IPv4\'s Total Length, this counts only what follows the fixed 40-byte header — extension headers included.',
    }),
    field({
      name: 'Next Header',
      value: `${nextHeader} (${nextName})`,
      offset: offset + 6,
      length: 1,
      layer: 3,
      key: 'ip6.nexthdr',
      why: EXTENSION_HEADERS[nextHeader]
        ? 'This is an IPv6 extension header rather than a transport protocol, so the chain has to be walked one more step to find Layer 4.'
        : `The transport header that follows is ${nextName}.`,
    }),
    field({
      name: 'Hop Limit',
      value: String(hopLimit),
      offset: offset + 7,
      length: 1,
      layer: 3,
      key: 'ip6.hoplimit',
      why:
        hopLimit === 255
          ? 'A hop limit of 255 is deliberate in Neighbour Discovery: a receiver that insists on 255 knows the packet cannot have been routed, so it must have come from the local link.'
          : `The packet can cross ${hopLimit} more router${hopLimit === 1 ? '' : 's'} before it is discarded.`,
      note: hopLimit <= 1 ? 'warn' : undefined,
    }),
    field({ name: 'Source Address', value: src, offset: offset + 8, length: 16, layer: 3, key: 'ip6.src', why: ipv6Nature(src) }),
    field({ name: 'Destination Address', value: dst, offset: offset + 24, length: 16, layer: 3, key: 'ip6.dst', why: ipv6Nature(dst) }),
  ];

  ctx.add({
    id: 'ipv6',
    name: 'Internet Protocol Version 6',
    abbr: 'IPv6',
    layer: 3,
    summary: `${src} -> ${dst}, next header ${nextName}, hop limit ${hopLimit}`,
    offset,
    length: 40,
    fields,
    payload: { offset: offset + 40, length: Math.min(payloadLength, Math.max(0, b.length - offset - 40)) },
  });

  ctx.source = src;
  ctx.destination = dst;
  ctx.ipSrcBytes = b.subarray(offset + 8, offset + 24);
  ctx.ipDstBytes = b.subarray(offset + 24, offset + 40);
  ctx.ipVersion = 6;
  ctx.transportEnd = Math.min(b.length, offset + 40 + payloadLength);
  ctx.info = `${nextName} ${src} -> ${dst}`;

  // Walk the extension-header chain until a real transport protocol shows up.
  let cursor = offset + 40;
  let proto = nextHeader;
  let guard = 0;
  while (EXTENSION_HEADERS[proto] && ctx.has(cursor, 2) && guard++ < 16) {
    const thisNext = b[cursor];
    const extLen = proto === 44 ? 8 : (b[cursor + 1] + 1) * 8;
    ctx.add({
      id: `ip6ext-${guard}`,
      name: `IPv6 ${EXTENSION_HEADERS[proto]} extension header`,
      abbr: 'IPv6-EXT',
      layer: 3,
      summary: `${extLen} bytes, next header ${IP_PROTOCOLS[thisNext] ?? thisNext}`,
      offset: cursor,
      length: extLen,
      fields: [
        field({
          name: 'Next Header',
          value: `${thisNext} (${IP_PROTOCOLS[thisNext] ?? EXTENSION_HEADERS[thisNext] ?? 'unknown'})`,
          offset: cursor,
          length: 1,
          layer: 3,
          key: 'ip6.nexthdr',
        }),
        field({
          name: 'Extension header data',
          value: hexPreview(b, cursor, extLen),
          offset: cursor,
          length: extLen,
          layer: 3,
          whatText:
            'IPv6 moved rarely used IPv4 header options into a chain of optional extension headers, so the common case stays a fixed 40 bytes that routers can process at line rate.',
        }),
      ],
    });
    cursor += extLen;
    proto = thisNext;
  }

  ctx.ipProtocol = proto;
  dispatchTransport(ctx, proto, cursor, IP_PROTOCOLS[proto] ?? `protocol ${proto}`);
}
