/**
 * Top-level dissection: turn a raw capture record into a fully dissected
 * packet, including the synthesised Layer 1 view that a PCAP file can offer.
 */

import type { CaptureMeta, DissectedPacket, Field, RawPacket } from '../types';
import { DissectContext, field } from './context';
import { dissectEthernet, addUnknownPayload } from './ethernet';
import { dissectIPv4 } from './ipv4';
import { dissectIPv6 } from './ipv6';
import { hex, readU16BE, readU32BE } from '../bytes';

export function dissectPacket(
  raw: RawPacket,
  meta: CaptureMeta,
  firstTimestamp: number,
  previousTimestamp: number | undefined,
): DissectedPacket {
  const ctx = new DissectContext(raw.bytes);
  const iface = meta.interfaces[raw.interfaceId] ?? meta.interfaces[0];
  const linkType = iface?.linkType ?? meta.linkType;

  addPhysicalLayer(ctx, raw, meta, linkType, previousTimestamp);

  if (raw.capturedLength < raw.originalLength) {
    ctx.warn(
      `This frame was sliced: ${raw.originalLength} bytes were on the wire but only ${raw.capturedLength} were saved. ` +
        'Upper-layer dissection will be incomplete.',
    );
  }

  try {
    dissectLinkLayer(ctx, linkType);
  } catch (error) {
    ctx.warn(`Dissection stopped early: ${error instanceof Error ? error.message : String(error)}`);
  }

  ctx.term(String(raw.index), ctx.protocol);

  return {
    ...raw,
    relativeTime: raw.timestamp - firstTimestamp,
    protocols: ctx.protocols,
    protocol: ctx.protocol,
    source: ctx.source || '-',
    destination: ctx.destination || '-',
    info: ctx.info || `${ctx.protocol} packet`,
    searchIndex: [...ctx.searchTerms].join(' '),
    warnings: ctx.warnings,
  };
}

function dissectLinkLayer(ctx: DissectContext, linkType: number): void {
  switch (linkType) {
    case 1:
      dissectEthernet(ctx, 0);
      break;
    case 0: {
      // BSD loopback: a 4-byte host-order address family precedes the IP header.
      if (!ctx.has(0, 4)) return;
      const af = readU32BE(ctx.bytes, 0);
      const afLe = ctx.bytes[0] | (ctx.bytes[1] << 8) | (ctx.bytes[2] << 16) | (ctx.bytes[3] << 24);
      const family = af === 2 || afLe === 2 ? 4 : 6;
      ctx.add({
        id: 'null',
        name: 'BSD loopback encapsulation',
        abbr: 'LOOPBACK',
        layer: 2,
        summary: `Address family ${family === 4 ? 'AF_INET' : 'AF_INET6'}`,
        offset: 0,
        length: 4,
        fields: [
          field({
            name: 'Address family',
            value: family === 4 ? 'AF_INET (IPv4)' : 'AF_INET6 (IPv6)',
            offset: 0,
            length: 4,
            layer: 2,
            whatText:
              'Loopback captures have no real Layer 2 header — there is no wire and no MAC address. The capture driver substitutes a 4-byte address family so the dissector still knows what follows.',
            why: 'A useful reminder that Layer 2 is about a specific medium. With no medium, there is nothing for it to do.',
          }),
        ],
        payload: { offset: 4, length: Math.max(0, ctx.bytes.length - 4) },
      });
      if (family === 4) dissectIPv4(ctx, 4);
      else dissectIPv6(ctx, 4);
      break;
    }
    case 101:
    case 228:
      dissectIPv4(ctx, 0);
      break;
    case 229:
      dissectIPv6(ctx, 0);
      break;
    case 113: {
      // Linux "cooked" capture: 16-byte pseudo-header, used when capturing on "any".
      if (!ctx.has(0, 16)) return;
      const proto = readU16BE(ctx.bytes, 14);
      ctx.add({
        id: 'sll',
        name: 'Linux cooked capture (SLL)',
        abbr: 'SLL',
        layer: 2,
        summary: `Protocol ${hex(proto, 4)}`,
        offset: 0,
        length: 16,
        fields: [
          field({
            name: 'Packet type',
            value: String(readU16BE(ctx.bytes, 0)),
            offset: 0,
            length: 2,
            layer: 2,
            whatText: '0 = to us, 1 = broadcast, 2 = multicast, 3 = to someone else, 4 = sent by us.',
          }),
          field({ name: 'Link-layer address type', value: String(readU16BE(ctx.bytes, 2)), offset: 2, length: 2, layer: 2, whatText: 'ARPHRD_* value describing the real interface type.' }),
          field({ name: 'Link-layer address', value: 'see hex pane', offset: 6, length: 8, layer: 2, whatText: 'The source hardware address, padded to 8 bytes.' }),
          field({
            name: 'Protocol',
            value: hex(proto, 4),
            offset: 14,
            length: 2,
            layer: 2,
            whatText: 'The EtherType of the payload.',
            why: 'This pseudo-header appears when tcpdump captures on the "any" pseudo-interface: there is no single real Layer 2 header to show, because frames come from several different interfaces.',
          }),
        ],
        payload: { offset: 16, length: Math.max(0, ctx.bytes.length - 16) },
      });
      if (proto === 0x0800) dissectIPv4(ctx, 16);
      else if (proto === 0x86dd) dissectIPv6(ctx, 16);
      else addUnknownPayload(ctx, 16, 'SLL');
      break;
    }
    case 276: {
      if (!ctx.has(0, 20)) return;
      const proto = readU16BE(ctx.bytes, 0);
      ctx.add({
        id: 'sll2',
        name: 'Linux cooked capture v2 (SLL2)',
        abbr: 'SLL2',
        layer: 2,
        summary: `Protocol ${hex(proto, 4)}`,
        offset: 0,
        length: 20,
        fields: [
          field({ name: 'Protocol', value: hex(proto, 4), offset: 0, length: 2, layer: 2, whatText: 'The EtherType of the payload.' }),
          field({ name: 'Interface index', value: String(readU32BE(ctx.bytes, 4)), offset: 4, length: 4, layer: 2, whatText: 'Which real interface the frame arrived on.' }),
        ],
        payload: { offset: 20, length: Math.max(0, ctx.bytes.length - 20) },
      });
      if (proto === 0x0800) dissectIPv4(ctx, 20);
      else if (proto === 0x86dd) dissectIPv6(ctx, 20);
      else addUnknownPayload(ctx, 20, 'SLL2');
      break;
    }
    default:
      ctx.warn(
        `Link type ${linkType} is not decoded by this tool. The frame bytes are still shown in the hex pane.`,
      );
      addUnknownPayload(ctx, 0, `Link type ${linkType}`);
      break;
  }
}

/**
 * Build the Layer 1 view.
 *
 * This is the layer students find most confusing, because a capture file
 * contains no Layer 1 data at all — the NIC consumed it. What it does contain
 * is metadata *about* the physical arrival of the frame, which is genuinely
 * Layer 1 information, and that is what this synthesises.
 */
function addPhysicalLayer(
  ctx: DissectContext,
  raw: RawPacket,
  meta: CaptureMeta,
  linkType: number,
  previousTimestamp: number | undefined,
): void {
  const iface = meta.interfaces[raw.interfaceId] ?? meta.interfaces[0];
  const date = new Date(raw.timestamp * 1000);
  const fraction = raw.timestamp - Math.floor(raw.timestamp);
  const stamp = `${date.toISOString().replace('Z', '')}${fraction.toFixed(9).slice(11)}Z`;
  const sliced = raw.capturedLength < raw.originalLength;
  const bits = raw.originalLength * 8;

  const fields: Field[] = [
    field({
      name: 'Frame number',
      value: String(raw.index),
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.number',
      synthetic: true,
    }),
    field({
      name: 'Arrival time',
      value: stamp,
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.arrival',
      synthetic: true,
      why: `Recorded with a resolution of 1/${iface?.timeResolution ?? 1e6} second by the capturing host's clock.`,
    }),
  ];

  if (previousTimestamp !== undefined) {
    const delta = raw.timestamp - previousTimestamp;
    fields.push(
      field({
        name: 'Time since previous frame',
        value: `${(delta * 1000).toFixed(3)} ms`,
        offset: 0,
        length: 0,
        layer: 1,
        key: 'frame.delta',
        synthetic: true,
        why:
          delta > 0.2
            ? 'A gap this large is usually the application thinking, a DNS lookup, or a retransmission timer — not the network being slow.'
            : 'Back-to-back frames like this are typical of a burst within one flow.',
      }),
    );
  }

  fields.push(
    field({
      name: 'Captured length',
      value: `${raw.capturedLength} bytes (${raw.capturedLength * 8} bits)`,
      offset: 0,
      length: raw.capturedLength,
      layer: 1,
      key: 'frame.caplen',
      synthetic: true,
      why: sliced
        ? `Only ${raw.capturedLength} of ${raw.originalLength} bytes were saved, because the capture ran with a snapshot length of ${iface?.snapLen ?? meta.snapLen}. Anything past that point is gone for good.`
        : 'The whole frame was saved, so every layer above can be dissected completely.',
      note: sliced ? 'warn' : undefined,
    }),
    field({
      name: 'Frame length on the wire',
      value: `${raw.originalLength} bytes (${bits} bits)`,
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.wirelen',
      synthetic: true,
      why:
        `At 1 Gbit/s these ${bits} bits occupy the medium for about ${((bits / 1e9) * 1e6).toFixed(2)} microseconds; at 100 Mbit/s, ${((bits / 1e8) * 1e6).toFixed(2)}. ` +
        'Serialisation delay like this is a real, physical component of latency, and it is the one thing in the whole capture that is unambiguously Layer 1.',
    }),
    field({
      name: 'Capture interface',
      value: `#${raw.interfaceId}${iface?.name ? ` — ${iface.name}` : ''}`,
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.iface',
      synthetic: true,
      why: iface?.description ? iface.description : undefined,
    }),
    field({
      name: 'Link-layer encapsulation',
      value: `${linkType} (${iface?.linkTypeName ?? meta.linkTypeName})`,
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.linktype',
      synthetic: true,
    }),
    field({
      name: 'What Layer 1 data is missing',
      value: 'Preamble, SFD, line coding, voltages/RF — and usually the FCS',
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.physical',
      synthetic: true,
      note: 'info',
    }),
    field({
      name: 'Frame Check Sequence',
      value: 'not present in this capture',
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.fcs',
      synthetic: true,
    }),
  );

  ctx.add({
    id: 'frame',
    name: 'Frame / capture metadata',
    abbr: 'FRAME',
    layer: 1,
    virtual: true,
    summary: `${raw.originalLength} bytes on the wire, ${raw.capturedLength} captured, interface #${raw.interfaceId}`,
    offset: 0,
    length: 0,
    fields,
  });
}
