/** Ethernet II / IEEE 802.3 framing, 802.1Q VLAN tags, and the ARP payload. */

import type { Field, ProtocolLayer } from '../types';
import { DissectContext, field } from './context';
import { formatIPv4, formatMac, hex, hexPreview, readU16BE } from '../bytes';
import { macNature, ouiVendor } from './oui';
import { dissectIPv4 } from './ipv4';
import { dissectIPv6 } from './ipv6';

export const ETHERTYPES: Record<number, string> = {
  0x0800: 'IPv4',
  0x0806: 'ARP',
  0x0842: 'Wake-on-LAN',
  0x8035: 'RARP',
  0x8100: '802.1Q VLAN',
  0x86dd: 'IPv6',
  0x8808: 'Ethernet flow control',
  0x8847: 'MPLS unicast',
  0x8848: 'MPLS multicast',
  0x88a8: '802.1ad QinQ',
  0x88cc: 'LLDP',
  0x8863: 'PPPoE Discovery',
  0x8864: 'PPPoE Session',
  0x9000: 'Ethernet Configuration Testing',
};

function macField(
  ctx: DissectContext,
  name: string,
  key: string,
  offset: number,
): Field {
  const mac = formatMac(ctx.bytes, offset);
  const vendor = ouiVendor(mac);
  const nature = macNature(mac);
  ctx.term(mac);
  const why =
    `This address is a ${nature.kind}. ${nature.detail}` +
    (vendor ? ` The OUI ${mac.slice(0, 8)} is registered to ${vendor}.` : '');
  return field({
    name,
    value: vendor ? `${mac} (${vendor})` : mac,
    offset,
    length: 6,
    layer: 2,
    key,
    why,
    children: [
      field({
        name: 'OUI (vendor prefix)',
        value: mac.slice(0, 8),
        offset,
        length: 3,
        layer: 2,
        whatText:
          'The Organisationally Unique Identifier: the first 24 bits, assigned by the IEEE to a hardware manufacturer.',
        why: vendor ? `Registered to ${vendor}.` : 'Not in this tool\'s small built-in vendor table.',
      }),
      field({
        name: 'U/L bit (bit 1 of byte 0)',
        value: (ctx.bytes[offset] & 0x02) === 0 ? '0 = globally unique' : '1 = locally administered',
        offset,
        length: 1,
        bits: { offset: 6, length: 1 },
        layer: 2,
        whatText:
          'Universal/Local bit. 0 means the address was assigned by the IEEE to a manufacturer; 1 means software invented it.',
      }),
      field({
        name: 'I/G bit (bit 0 of byte 0)',
        value: (ctx.bytes[offset] & 0x01) === 0 ? '0 = unicast' : '1 = multicast/broadcast',
        offset,
        length: 1,
        bits: { offset: 7, length: 1 },
        layer: 2,
        whatText:
          'Individual/Group bit. 0 addresses exactly one interface; 1 addresses a group, and switches flood it.',
      }),
    ],
  });
}

export function dissectEthernet(ctx: DissectContext, offset: number): void {
  if (!ctx.has(offset, 14)) {
    ctx.truncated('Ethernet', offset, 14);
    return;
  }

  const dstField = macField(ctx, 'Destination MAC', 'eth.dst', offset);
  const srcField = macField(ctx, 'Source MAC', 'eth.src', offset + 6);
  const dstMac = formatMac(ctx.bytes, offset);
  const srcMac = formatMac(ctx.bytes, offset + 6);

  const fields: Field[] = [dstField, srcField];
  let cursor = offset + 12;
  let etherType = readU16BE(ctx.bytes, cursor);
  const vlanIds: number[] = [];

  // Walk any stack of 802.1Q / 802.1ad tags before the real EtherType.
  while ((etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100) && ctx.has(cursor, 4)) {
    const tci = readU16BE(ctx.bytes, cursor + 2);
    const pcp = (tci >> 13) & 0x07;
    const dei = (tci >> 12) & 0x01;
    const vid = tci & 0x0fff;
    vlanIds.push(vid);
    ctx.term(`vlan${vid}`, 'vlan');
    fields.push(
      field({
        name: etherType === 0x88a8 ? 'Service VLAN tag (802.1ad)' : 'VLAN tag (802.1Q)',
        value: `VLAN ${vid}, priority ${pcp}`,
        offset: cursor,
        length: 4,
        layer: 2,
        whatText:
          'A four-byte tag inserted between the source MAC and the EtherType. It lets one physical link carry many separate broadcast domains — this is what makes a trunk port a trunk port.',
        why: `This frame belongs to VLAN ${vid}. A switch will only forward it out of ports that are members of that VLAN, or out of another trunk with the tag intact.`,
        children: [
          field({
            name: 'Tag Protocol Identifier',
            value: hex(etherType, 4),
            offset: cursor,
            length: 2,
            layer: 2,
            whatText: '0x8100 marks a customer VLAN tag; 0x88A8 marks a provider (QinQ) tag.',
          }),
          field({
            name: 'Priority Code Point (PCP)',
            value: String(pcp),
            offset: cursor + 2,
            length: 2,
            bits: { offset: 0, length: 3 },
            layer: 2,
            key: 'vlan.pcp',
            why:
              pcp === 0
                ? 'Priority 0 is best effort — the default for ordinary data.'
                : `Priority ${pcp} asks switches to put this frame in a higher-priority queue (5 is typical for voice).`,
          }),
          field({
            name: 'Drop Eligible Indicator',
            value: String(dei),
            offset: cursor + 2,
            length: 2,
            bits: { offset: 3, length: 1 },
            layer: 2,
            key: 'vlan.dei',
          }),
          field({
            name: 'VLAN Identifier',
            value: String(vid),
            offset: cursor + 2,
            length: 2,
            bits: { offset: 4, length: 12 },
            layer: 2,
            key: 'vlan.id',
          }),
        ],
      }),
    );
    cursor += 4;
    etherType = readU16BE(ctx.bytes, cursor);
  }

  const typeName = ETHERTYPES[etherType];
  if (etherType <= 1500) {
    fields.push(
      field({
        name: 'Length (IEEE 802.3)',
        value: String(etherType),
        offset: cursor,
        length: 2,
        layer: 2,
        key: 'eth.len',
        why: `Values of 1500 or less are a payload length, so this is an 802.3 frame carrying ${etherType} bytes of LLC data rather than an Ethernet II frame.`,
      }),
    );
  } else {
    fields.push(
      field({
        name: 'EtherType',
        value: `${hex(etherType, 4)}${typeName ? ` (${typeName})` : ''}`,
        offset: cursor,
        length: 2,
        layer: 2,
        key: 'eth.type',
        why: typeName
          ? `The next header is ${typeName}. This single field is the hand-off point from Layer 2 to Layer 3.`
          : 'This EtherType is not one the tool recognises, so the payload is shown as raw bytes.',
      }),
    );
  }
  cursor += 2;

  const headerLength = cursor - offset;
  const layer: ProtocolLayer = {
    id: 'eth',
    name: 'Ethernet II',
    abbr: 'Ethernet',
    layer: 2,
    summary: `${srcMac} -> ${dstMac}${vlanIds.length ? ` (VLAN ${vlanIds.join(' > ')})` : ''}`,
    offset,
    length: headerLength,
    fields,
    payload: { offset: cursor, length: Math.max(0, ctx.bytes.length - cursor) },
  };
  ctx.add(layer);

  ctx.source = srcMac;
  ctx.destination = dstMac;
  ctx.info = `${typeName ?? hex(etherType, 4)} frame`;

  switch (etherType) {
    case 0x0800:
      dissectIPv4(ctx, cursor);
      break;
    case 0x86dd:
      dissectIPv6(ctx, cursor);
      break;
    case 0x0806:
    case 0x8035:
      dissectArp(ctx, cursor, etherType === 0x8035);
      break;
    default:
      addUnknownPayload(ctx, cursor, typeName ?? `EtherType ${hex(etherType, 4)}`);
      break;
  }
}

export function addUnknownPayload(ctx: DissectContext, offset: number, label: string): void {
  const length = Math.max(0, ctx.bytes.length - offset);
  if (length === 0) return;
  ctx.add({
    id: 'data',
    name: `${label} payload`,
    abbr: 'DATA',
    layer: 7,
    summary: `${length} bytes not decoded by this tool`,
    offset,
    length,
    fields: [
      field({
        name: 'Payload bytes',
        value: hexPreview(ctx.bytes, offset, length),
        offset,
        length,
        layer: 7,
        key: 'payload.raw',
        why: `No dissector claimed these ${length} bytes. Use the hex pane: printable ASCII on the right often reveals the protocol even when the tool cannot name it.`,
      }),
    ],
  });
}

const ARP_OPS: Record<number, string> = {
  1: 'Request',
  2: 'Reply',
  3: 'RARP Request',
  4: 'RARP Reply',
};

function dissectArp(ctx: DissectContext, offset: number, rarp: boolean): void {
  if (!ctx.has(offset, 28)) {
    ctx.truncated('ARP', offset, 28);
    addUnknownPayload(ctx, offset, 'ARP');
    return;
  }
  const b = ctx.bytes;
  const htype = readU16BE(b, offset);
  const ptype = readU16BE(b, offset + 2);
  const hlen = b[offset + 4];
  const plen = b[offset + 5];
  const op = readU16BE(b, offset + 6);
  const sha = formatMac(b, offset + 8);
  const spa = formatIPv4(b, offset + 14);
  const tha = formatMac(b, offset + 18);
  const tpa = formatIPv4(b, offset + 24);
  ctx.term(spa, tpa, sha, tha, 'arp');

  const gratuitous = spa === tpa;
  const probe = spa === '0.0.0.0';

  const fields: Field[] = [
    field({
      name: 'Hardware type',
      value: `${htype}${htype === 1 ? ' (Ethernet)' : ''}`,
      offset,
      length: 2,
      layer: 2,
      key: 'arp.htype',
    }),
    field({
      name: 'Protocol type',
      value: `${hex(ptype, 4)}${ptype === 0x0800 ? ' (IPv4)' : ''}`,
      offset: offset + 2,
      length: 2,
      layer: 2,
      key: 'arp.ptype',
    }),
    field({ name: 'Hardware address length', value: String(hlen), offset: offset + 4, length: 1, layer: 2, key: 'arp.hlen' }),
    field({ name: 'Protocol address length', value: String(plen), offset: offset + 5, length: 1, layer: 2, key: 'arp.plen' }),
    field({
      name: 'Operation',
      value: `${op} (${ARP_OPS[op] ?? 'unknown'})`,
      offset: offset + 6,
      length: 2,
      layer: 2,
      key: 'arp.op',
      why:
        op === 1
          ? `This is a question, sent to the broadcast MAC so every station on the segment hears it: "who owns ${tpa}?" Only the owner answers.`
          : op === 2
            ? `This is the answer: ${spa} lives at ${sha}. The reply is unicast straight back to the asker, and both machines cache the mapping.`
            : 'Reverse ARP, an obsolete way for a diskless station to learn its own IP from its MAC.',
    }),
    field({ name: 'Sender MAC address', value: sha, offset: offset + 8, length: 6, layer: 2, key: 'arp.sha' }),
    field({
      name: 'Sender IP address',
      value: spa,
      offset: offset + 14,
      length: 4,
      layer: 2,
      key: 'arp.spa',
      why: probe
        ? 'A sender IP of 0.0.0.0 makes this an ARP probe: the host is checking whether an address is already in use before claiming it (duplicate address detection).'
        : undefined,
    }),
    field({
      name: 'Target MAC address',
      value: tha,
      offset: offset + 18,
      length: 6,
      layer: 2,
      key: 'arp.tha',
      why:
        op === 1
          ? 'All zeroes, as it must be in a request — this is the unknown the request exists to discover. Note that this is the ARP payload field, not the Ethernet destination, which is the broadcast address.'
          : undefined,
    }),
    field({ name: 'Target IP address', value: tpa, offset: offset + 24, length: 4, layer: 2, key: 'arp.tpa' }),
  ];

  ctx.add({
    id: 'arp',
    name: rarp ? 'Reverse Address Resolution Protocol' : 'Address Resolution Protocol',
    abbr: rarp ? 'RARP' : 'ARP',
    layer: 2,
    summary: op === 1 ? `Who has ${tpa}? Tell ${spa}` : `${spa} is at ${sha}`,
    offset,
    length: 28,
    fields,
  });

  ctx.source = spa === '0.0.0.0' ? sha : spa;
  ctx.destination = op === 1 ? 'Broadcast' : tpa;
  ctx.info =
    op === 1
      ? gratuitous
        ? `Gratuitous ARP: ${spa} is announcing itself at ${sha}`
        : `Who has ${tpa}? Tell ${spa}`
      : `${spa} is at ${sha}`;

  // ARP is one of the very few protocols that genuinely stops at Layer 2, and
  // saying so explicitly is more useful to a student than silence.
  ctx.add({
    id: 'arp-osi',
    name: 'No network layer — ARP stops at Layer 2',
    absence: true,
    abbr: 'ARP',
    layer: 3,
    virtual: true,
    summary: 'ARP is a pure Layer 2 protocol: there is no IP header in this frame.',
    offset,
    length: 0,
    fields: [
      field({
        name: 'No Network layer',
        value: 'ARP rides directly on Ethernet',
        offset,
        length: 0,
        layer: 3,
        synthetic: true,
        whatText:
          'ARP has its own EtherType (0x0806) and is carried straight inside the Ethernet frame. It carries IPv4 addresses as data, but it is not encapsulated in IP — which is why an ARP frame can never be routed off the local segment.',
        why: 'This is the classic exam question: ARP contains IP addresses but is not an IP protocol. It sits alongside IP at the boundary of Layer 2 and Layer 3, not on top of it.',
      }),
    ],
  });

  const padding = ctx.bytes.length - (offset + 28);
  if (padding > 0) {
    ctx.add({
      id: 'eth-padding',
      name: 'Ethernet padding',
      abbr: 'PAD',
      layer: 2,
      trailer: true,
      summary: `${padding} bytes of padding to reach the 60-byte minimum frame`,
      offset: offset + 28,
      length: padding,
      fields: [
        field({
          name: 'Padding',
          value: hexPreview(ctx.bytes, offset + 28, padding),
          offset: offset + 28,
          length: padding,
          layer: 2,
          key: 'eth.padding',
          why: `An ARP message is only 28 bytes, and with the 14-byte Ethernet header that is 42 — below the 60-byte minimum (64 with the FCS). The NIC pads it with ${padding} bytes so collision detection on legacy half-duplex Ethernet still works.`,
        }),
      ],
    });
  }
}
