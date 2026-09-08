/**
 * Top-level dissection: turn a raw capture record into a fully dissected
 * packet, including the synthesised Layer 1 view that a PCAP file can offer.
 */

import type { CaptureMeta, DissectedPacket, Field, RawPacket } from '../types';
import { DissectContext, field } from './context';
import { dissectEthernet, addUnknownPayload } from './ethernet';
import { dissectIPv4 } from './ipv4';
import { dissectIPv6 } from './ipv6';
import { dissectRadiotap } from './radiotap';
import { dissect80211 } from './ieee80211';
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
    case 127:
      dissectRadiotap(ctx, 0);
      break;
    case 105:
      dissect80211(ctx, 0);
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
  const resolution = iface?.timeResolution ?? 1e6;
  const ethernetLike = linkType === 1;

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
      why:
        resolution >= 1e9
          ? 'Recorded with nanosecond resolution. That precision normally means the timestamp was taken by the adapter itself, at the PHY, rather than by the operating system once the frame reached the driver.'
          : `Recorded with a resolution of 1/${resolution} second by the capturing host's clock. Microsecond resolution usually means a software timestamp taken in the driver, so it includes some interrupt and scheduling jitter.`,
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
      why: serialisationNote(bits, iface?.speed),
    }),
  );

  // On Ethernet the true medium occupancy is larger than the frame: preamble,
  // start-of-frame delimiter, the FCS the adapter removed, and the mandatory
  // inter-frame gap all consume airtime that never appears in the capture.
  if (ethernetLike) {
    const overheadBytes = 8 + 4 + 12;
    const totalBits = (raw.originalLength + overheadBytes) * 8;
    fields.push(
      field({
        name: 'True medium occupancy',
        value: `${raw.originalLength + overheadBytes} byte-times (${totalBits} bit-times)`,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText:
          'What the frame really costs on the wire: the captured length plus 7 bytes of preamble, 1 byte of start-of-frame delimiter, the 4-byte frame check sequence the adapter stripped, and the 12-byte inter-frame gap that must follow.',
        why:
          `Even "bytes on wire" understates the physical footprint by ${overheadBytes} bytes. It matters most for small frames: a 64-byte frame occupies 88 byte-times, so a link saturated with minimum-sized frames wastes over a quarter of its capacity on framing overhead that no capture file records.`,
      }),
    );
  }

  fields.push(
    field({
      name: 'Capture interface',
      value: `#${raw.interfaceId}${iface?.name ? ` — ${iface.name}` : ''}`,
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.iface',
      synthetic: true,
      why:
        meta.format === 'pcapng'
          ? 'Read from the pcapng Interface Description Block, which names the exact port that ingested the frame. A pcapng file can interleave several interfaces in one capture, and this is what tells them apart.'
          : iface?.description,
    }),
  );

  if (iface?.description) {
    fields.push(
      field({
        name: 'Interface description',
        value: iface.description,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'Free text the capturing tool recorded about this interface (pcapng option if_description).',
      }),
    );
  }
  if (iface?.hardware) {
    fields.push(
      field({
        name: 'Adapter hardware',
        value: iface.hardware,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'The physical adapter the capture came from (pcapng option if_hardware).',
        why: 'The adapter decides what you can and cannot see. Checksum offload, large receive offload and VLAN tag stripping all happen in this chip, and each of them changes what ends up in the file.',
      }),
    );
  }
  if (iface?.os) {
    fields.push(
      field({
        name: 'Capture host OS',
        value: iface.os,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'The operating system that ran the capture (pcapng option if_os).',
      }),
    );
  }
  if (iface?.speed) {
    fields.push(
      field({
        name: 'Interface speed',
        value: formatBitRate(iface.speed),
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'The nominal bit rate of the link, recorded by the capture tool (pcapng option if_speed).',
        why: `At ${formatBitRate(iface.speed)} these ${bits} bits take ${formatDuration(bits / iface.speed)} to clock onto the medium. That is serialisation delay: a real, physical component of latency that no amount of protocol tuning can remove.`,
      }),
    );
  }
  if (iface?.filter) {
    fields.push(
      field({
        name: 'Capture filter in effect',
        value: iface.filter,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'The BPF filter the capture ran with (pcapng option if_filter).',
        why: 'Worth checking before concluding traffic is missing: the most common reason a packet is not in a capture is that the filter excluded it.',
      }),
    );
  }

  const options = raw.options;
  if (options?.direction !== undefined && options.direction !== 0) {
    fields.push(
      field({
        name: 'Direction',
        value: options.direction === 1 ? 'inbound (received)' : 'outbound (transmitted)',
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'Which way the frame was moving through the adapter, from the pcapng epb_flags option.',
        why:
          options.direction === 2
            ? 'This frame was transmitted by the capturing host. That is worth knowing before you trust its checksums: on an outbound frame the capture point sits before the hardware fills them in, so bad checksums here almost always mean offload rather than corruption.'
            : 'This frame was received from the network, so its checksums were computed by the sender and are meaningful.',
      }),
    );
  }
  if (options?.receptionType) {
    const types = ['unspecified', 'unicast', 'multicast', 'broadcast', 'promiscuous'];
    fields.push(
      field({
        name: 'Reception type',
        value: types[options.receptionType] ?? String(options.receptionType),
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'How the adapter came to receive this frame.',
        why:
          options.receptionType === 4
            ? 'Received promiscuously: the frame was not addressed to this host at all, and the adapter only saw it because it was told to accept everything. On a switched network that usually means a mirror port or a tap.'
            : undefined,
      }),
    );
  }
  if (options?.errorFlags) {
    fields.push(
      field({
        name: 'Link-layer error flags',
        value: hex(options.errorFlags, 4),
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        note: 'error',
        whatText: 'Errors the capture hardware itself reported, such as a symbol error, a CRC failure or an oversized frame.',
        why: 'These are faults detected below the frame — at the physical layer — and they point at cabling, optics or interference rather than at anything a protocol analyst can fix.',
      }),
    );
  }
  if (options?.comment) {
    fields.push(
      field({
        name: 'Packet comment',
        value: options.comment,
        offset: 0,
        length: 0,
        layer: 1,
        synthetic: true,
        whatText: 'A note stored alongside this frame in the pcapng file (option opt_comment).',
        why: 'Comments survive in the file, which makes pcapng captures a reasonable way to hand annotated evidence to someone else.',
      }),
    );
  }

  fields.push(
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
      value:
        linkType === 127
          ? 'Raw I/Q samples and the PLCP preamble — but the radio\'s own measurements survive, above'
          : 'Preamble, SFD, line coding, voltages/RF — and usually the FCS',
      offset: 0,
      length: 0,
      layer: 1,
      key: 'frame.physical',
      synthetic: true,
      note: 'info',
      why:
        linkType === 127
          ? 'A monitor-mode Wi-Fi capture is the exception to the usual rule. The driver prepends a radiotap header carrying what the radio actually measured — frequency, signal strength in dBm, antenna, modulation — so this frame has real physical-layer values, with real byte offsets you can highlight in the hex pane.'
          : undefined,
    }),
    field({
      name: 'Frame Check Sequence',
      value: fcsDescription(options?.fcsLength ?? iface?.fcsLength),
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
    summary:
      `${raw.originalLength} bytes on the wire, ${raw.capturedLength} captured` +
      `${iface?.name ? `, ${iface.name}` : `, interface #${raw.interfaceId}`}` +
      `${raw.options?.direction === 2 ? ', outbound' : raw.options?.direction === 1 ? ', inbound' : ''}`,
    offset: 0,
    length: 0,
    fields,
  });
}

/** How long these bits take to clock onto the medium, at whatever rate we know. */
function serialisationNote(bits: number, speed: number | undefined): string {
  if (speed) {
    return (
      `At the interface's recorded ${formatBitRate(speed)} these ${bits} bits occupy the medium for ` +
      `${formatDuration(bits / speed)}. Serialisation delay like this is a real, physical component of latency, ` +
      'and it is the one number in the whole capture that is unambiguously Layer 1.'
    );
  }
  return (
    `At 1 Gbit/s these ${bits} bits occupy the medium for about ${formatDuration(bits / 1e9)}; at 100 Mbit/s, ` +
    `${formatDuration(bits / 1e8)}. Serialisation delay like this is a real, physical component of latency, and it ` +
    'is the one number in the whole capture that is unambiguously Layer 1.'
  );
}

function formatBitRate(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(bps % 1e9 === 0 ? 0 : 1)} Gbit/s`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(bps % 1e6 === 0 ? 0 : 1)} Mbit/s`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(0)} kbit/s`;
  return `${bps} bit/s`;
}

function formatDuration(seconds: number): string {
  if (seconds >= 1e-3) return `${(seconds * 1e3).toFixed(2)} ms`;
  if (seconds >= 1e-6) return `${(seconds * 1e6).toFixed(2)} µs`;
  return `${(seconds * 1e9).toFixed(0)} ns`;
}

function fcsDescription(fcsLengthBits: number | undefined): string {
  if (fcsLengthBits === undefined) return 'not present in this capture';
  if (fcsLengthBits === 0) return 'stripped by the adapter (0 bits recorded)';
  return `${fcsLengthBits} bits still attached to each frame`;
}
