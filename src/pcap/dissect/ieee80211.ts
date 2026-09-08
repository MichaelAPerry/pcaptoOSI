/**
 * IEEE 802.11 (Wi-Fi) data link dissection.
 *
 * Worth having in a teaching tool for two reasons. First, it is the clearest
 * demonstration that Layer 2 is not "the Ethernet layer": same job, completely
 * different header, four address fields instead of two. Second, a wireless
 * capture contains whole classes of frame — beacons, acknowledgements, RTS/CTS
 * — that exist purely to manage a shared physical medium, and therefore have
 * nothing above Layer 2 at all.
 */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { formatMac, hex, readU16BE } from '../bytes';
import { ETHERTYPES } from './ethernet';
import { dissectIPv4 } from './ipv4';
import { dissectIPv6 } from './ipv6';
import { frequencyToChannel } from './radiotap';

const TYPE_NAMES: Record<number, string> = { 0: 'Management', 1: 'Control', 2: 'Data', 3: 'Extension' };

const SUBTYPES: Record<number, Record<number, string>> = {
  0: {
    0: 'Association Request',
    1: 'Association Response',
    2: 'Reassociation Request',
    3: 'Reassociation Response',
    4: 'Probe Request',
    5: 'Probe Response',
    8: 'Beacon',
    9: 'ATIM',
    10: 'Disassociation',
    11: 'Authentication',
    12: 'Deauthentication',
    13: 'Action',
  },
  1: {
    7: 'Control Wrapper',
    8: 'Block Ack Request',
    9: 'Block Ack',
    10: 'PS-Poll',
    11: 'RTS',
    12: 'CTS',
    13: 'Acknowledgement',
    14: 'CF-End',
  },
  2: {
    0: 'Data',
    4: 'Null (no data)',
    8: 'QoS Data',
    12: 'QoS Null (no data)',
  },
};

/** Explain what this frame type is doing in the cell. */
function describeSubtype(type: number, subtype: number): string {
  if (type === 0) {
    switch (subtype) {
      case 8:
        return 'A beacon: the access point announcing the cell roughly ten times a second, carrying the SSID, supported rates, channel and capabilities. Beacons are why your device can list networks without associating to any of them — and they are sent at the lowest supported rate so the furthest client can still hear them.';
      case 4:
        return 'A probe request: a client actively asking "is anyone here?" rather than waiting for a beacon. Probe requests are broadcast, unencrypted, and often carry the names of networks the device has joined before — which is why they are a well-known privacy leak.';
      case 5:
        return 'A probe response: an access point answering a probe request directly, with much the same contents as a beacon.';
      case 11:
        return 'Authentication. In modern WPA2/WPA3 networks this is a vestigial two-message exchange; the real authentication happens afterwards in the 4-way handshake.';
      case 12:
        return 'Deauthentication. Because these frames are unprotected on networks without management frame protection, forging them is the classic Wi-Fi denial-of-service and the first step of a handshake-capture attack.';
      default:
        return 'A management frame: 802.11 traffic that builds and maintains the cell rather than carrying user data.';
    }
  }
  if (type === 1) {
    switch (subtype) {
      case 13:
        return 'An acknowledgement. Every unicast Wi-Fi frame must be acknowledged within microseconds or the sender retransmits — reliability at Layer 2, which wired Ethernet never bothers with because collisions and loss are so much rarer on a cable.';
      case 11:
        return 'Request To Send: reserving the medium before a large transmission, so that stations which cannot hear each other directly (the hidden node problem) do not talk over one another.';
      case 12:
        return 'Clear To Send: the reservation being granted. Every station that hears it stays quiet for the stated duration.';
      default:
        return 'A control frame: pure medium-access machinery, with no payload of any kind.';
    }
  }
  if (subtype === 4 || subtype === 12) {
    return 'A null data frame. It carries nothing; its only purpose is the power-management bit in the header, which tells the access point to start or stop buffering frames for a sleeping client.';
  }
  return 'A data frame — the only 802.11 frame type that carries anything from the layers above.';
}

export function dissect80211(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 10)) {
    ctx.truncated('IEEE 802.11', offset, 10);
    return;
  }

  const fc0 = b[offset];
  const fc1 = b[offset + 1];
  const version = fc0 & 0x03;
  const type = (fc0 >> 2) & 0x03;
  const subtype = (fc0 >> 4) & 0x0f;
  const toDs = (fc1 & 0x01) !== 0;
  const fromDs = (fc1 & 0x02) !== 0;
  const moreFrag = (fc1 & 0x04) !== 0;
  const retry = (fc1 & 0x08) !== 0;
  const powerMgmt = (fc1 & 0x10) !== 0;
  const moreData = (fc1 & 0x20) !== 0;
  const protectedFrame = (fc1 & 0x40) !== 0;

  const subtypeName = SUBTYPES[type]?.[subtype] ?? `subtype ${subtype}`;
  const duration = b[offset + 2] | (b[offset + 3] << 8);
  const addr1 = formatMac(b, offset + 4);

  ctx.term('802.11', 'wlan', subtypeName.toLowerCase(), addr1);

  const fields: Field[] = [
    field({
      name: 'Frame Control',
      value: `${TYPE_NAMES[type]} / ${subtypeName}`,
      offset,
      length: 2,
      layer: 2,
      whatText: 'Two bytes that classify every 802.11 frame: protocol version, type, subtype, and eight flag bits describing where the frame is going and how it should be handled.',
      why: describeSubtype(type, subtype),
      children: [
        field({ name: 'Protocol version', value: String(version), offset, length: 1, bits: { offset: 6, length: 2 }, layer: 2, whatText: 'Always 0; 802.11 has never revised its frame format incompatibly.' }),
        field({
          name: 'Type',
          value: `${type} (${TYPE_NAMES[type]})`,
          offset,
          length: 1,
          bits: { offset: 4, length: 2 },
          layer: 2,
          whatText: 'Management builds the cell, Control manages access to the medium, Data carries everything above Layer 2.',
        }),
        field({ name: 'Subtype', value: `${subtype} (${subtypeName})`, offset, length: 1, bits: { offset: 0, length: 4 }, layer: 2, whatText: 'Which specific frame within the type.' }),
        field({
          name: 'To DS / From DS',
          value: `${toDs ? 1 : 0} / ${fromDs ? 1 : 0}`,
          offset: offset + 1,
          length: 1,
          bits: { offset: 6, length: 2 },
          layer: 2,
          whatText: 'Whether the frame is heading into the wired distribution system, coming out of it, both (a wireless bridge) or neither (a direct station-to-station frame).',
          why: 'These two bits decide what the three address fields below actually mean. That is the part of 802.11 that catches everyone out: unlike Ethernet, you cannot read a Wi-Fi header\'s addresses without first reading these bits.',
        }),
        field({ name: 'More Fragments', value: moreFrag ? '1' : '0', offset: offset + 1, length: 1, bits: { offset: 5, length: 1 }, layer: 2, whatText: 'Set on every fragment but the last.' }),
        field({
          name: 'Retry',
          value: retry ? '1 = retransmission' : '0',
          offset: offset + 1,
          length: 1,
          bits: { offset: 4, length: 1 },
          layer: 2,
          whatText: 'Set when this frame is a retransmission of one that was not acknowledged.',
          why: retry
            ? 'This frame has been sent before. A high retry rate is the single most useful health signal in a Wi-Fi capture: it means frames are being lost on the air, from interference, distance or contention — long before any of it shows up as a TCP retransmission.'
            : undefined,
          note: retry ? 'warn' : undefined,
        }),
        field({
          name: 'Power Management',
          value: powerMgmt ? '1 = station is going to sleep' : '0 = station is awake',
          offset: offset + 1,
          length: 1,
          bits: { offset: 3, length: 1 },
          layer: 2,
          whatText: 'Tells the access point whether to buffer frames for this station.',
          why: 'There is no equivalent on Ethernet. A wireless station spends most of its life with the radio off, and this bit is how it coordinates that with the access point.',
        }),
        field({ name: 'More Data', value: moreData ? '1' : '0', offset: offset + 1, length: 1, bits: { offset: 2, length: 1 }, layer: 2, whatText: 'The access point has more buffered frames for a sleeping station.' }),
        field({
          name: 'Protected Frame',
          value: protectedFrame ? '1 = encrypted' : '0 = clear',
          offset: offset + 1,
          length: 1,
          bits: { offset: 1, length: 1 },
          layer: 2,
          whatText: 'Whether the frame body is encrypted with WEP, TKIP, CCMP or GCMP.',
          why: protectedFrame
            ? 'The payload is encrypted at Layer 2, so nothing above the 802.11 header can be read without the session keys — note that this is link encryption, entirely separate from any TLS inside it.'
            : 'The body is in the clear. Management and control frames are normally unprotected unless the network enables 802.11w management frame protection.',
        }),
      ],
    }),
    field({
      name: 'Duration / ID',
      value: `${duration} µs`,
      offset: offset + 2,
      length: 2,
      layer: 2,
      whatText: 'How long the sender expects to keep using the medium, in microseconds.',
      why: 'Every station that hears this frame sets a countdown called the Network Allocation Vector and stays silent for that long, even if it cannot decode the frame itself. This is virtual carrier sense — collision *avoidance*, because a radio cannot listen while it transmits and so cannot detect collisions the way Ethernet does.',
    }),
  ];

  // Address interpretation depends entirely on the To DS / From DS bits.
  let cursor = offset + 4;
  const isControl = type === 1;
  const addressCount = isControl ? (subtype === 13 || subtype === 12 ? 1 : 2) : toDs && fromDs ? 4 : 3;

  const roles = isControl
    ? ['Receiver address (RA)', 'Transmitter address (TA)']
    : toDs && fromDs
      ? ['Receiver address (RA)', 'Transmitter address (TA)', 'Destination address (DA)', 'Source address (SA)']
      : toDs
        ? ['BSSID (the access point)', 'Source address (SA)', 'Destination address (DA)']
        : fromDs
          ? ['Destination address (DA)', 'BSSID (the access point)', 'Source address (SA)']
          : ['Destination address (DA)', 'Source address (SA)', 'BSSID'];

  const addresses: string[] = [];
  for (let i = 0; i < addressCount; i++) {
    // The sequence control field sits between address 3 and address 4.
    if (i === 3) cursor += 2;
    if (!ctx.has(cursor, 6)) break;
    const mac = formatMac(b, cursor);
    addresses.push(mac);
    ctx.term(mac);
    fields.push(
      field({
        name: `Address ${i + 1} — ${roles[i]}`,
        value: mac === 'ff:ff:ff:ff:ff:ff' ? `${mac} (broadcast)` : mac,
        offset: cursor,
        length: 6,
        layer: 2,
        whatText: roles[i],
        why:
          i === 0 && roles[i].startsWith('BSSID')
            ? 'The BSSID identifies the cell itself — normally the access point\'s own radio MAC. Every frame in a cell carries it, which is how overlapping networks on the same channel stay separable.'
            : i === 0
              ? 'The first address is always the immediate receiver on the air, which is what a station compares against its own MAC to decide whether to bother decoding the rest.'
              : undefined,
      }),
    );
    cursor += 6;
  }

  if (!isControl && ctx.has(cursor - (addressCount > 3 ? 8 : 0), 2)) {
    const seqOffset = addressCount > 3 ? cursor - 8 : cursor;
    if (ctx.has(seqOffset, 2)) {
      const seq = b[seqOffset] | (b[seqOffset + 1] << 8);
      fields.push(
        field({
          name: 'Sequence Control',
          value: `sequence ${seq >> 4}, fragment ${seq & 0x0f}`,
          offset: seqOffset,
          length: 2,
          layer: 2,
          whatText: 'A 12-bit sequence number and a 4-bit fragment number.',
          why: 'The receiver uses it to throw away duplicates. Because every unicast frame is acknowledged, a lost acknowledgement makes the sender retransmit a frame that in fact arrived — so Layer 2 needs its own duplicate detection.',
        }),
      );
      if (addressCount <= 3) cursor += 2;
    }
  }

  // QoS data frames carry two extra bytes of access-category information.
  const isQos = type === 2 && (subtype & 0x08) !== 0;
  if (isQos && ctx.has(cursor, 2)) {
    const qos = b[cursor] | (b[cursor + 1] << 8);
    const tid = qos & 0x0f;
    const AC = ['Best Effort', 'Background', 'Background', 'Best Effort', 'Video', 'Video', 'Voice', 'Voice'];
    fields.push(
      field({
        name: 'QoS Control',
        value: `TID ${tid} (${AC[tid & 0x07]})`,
        offset: cursor,
        length: 2,
        layer: 2,
        whatText: 'The traffic identifier, which maps to one of four access categories: voice, video, best effort and background.',
        why: 'Wi-Fi implements quality of service physically rather than by queueing: a voice frame waits a shorter random backoff before transmitting than a background frame does, so it statistically wins access to the air. This is Layer 2 doing what DSCP asks for at Layer 3.',
      }),
    );
    cursor += 2;
  }

  const headerLength = cursor - offset;
  const summary =
    type === 2
      ? `${subtypeName}, ${addresses[1] ?? '?'} → ${addresses[0] ?? '?'}`
      : `${subtypeName}${addresses[0] ? `, RA ${addresses[0]}` : ''}`;

  ctx.add({
    id: 'wlan',
    name: 'IEEE 802.11 wireless LAN',
    abbr: '802.11',
    layer: 2,
    summary,
    offset,
    length: headerLength,
    fields,
    payload: { offset: cursor, length: Math.max(0, b.length - cursor) },
  });

  // An acknowledgement carries only the receiver's address. Who sent it is
  // implied purely by timing — it is the station that was addressed microseconds
  // earlier — which is worth showing rather than papering over.
  ctx.source = addresses[1] ?? (isControl && addressCount === 1 ? '— (not in frame)' : '-');
  ctx.destination = addresses[0] ?? '-';
  ctx.info = `${subtypeName}`;

  if (type === 0) {
    dissectManagementBody(ctx, cursor, subtype, subtypeName);
    return;
  }
  if (isControl && addressCount === 1) {
    fields.push(
      field({
        name: 'Transmitter address',
        value: 'not carried in this frame',
        offset,
        length: 0,
        layer: 2,
        synthetic: true,
        whatText:
          'A bare acknowledgement has room for one address only: the station it is addressed to.',
        why: 'Who sent it is inferred entirely from timing — an acknowledgement follows the frame it acknowledges by a fixed short interframe space, so no other station could be transmitting. That is how far 802.11 will go to save airtime on a frame it sends after every single unicast transmission.',
      }),
    );
  }

  if (type === 1) {
    // Control frames end here: no payload exists at all.
    ctx.add({
      id: 'wlan-control',
      name: 'No layers above Layer 2',
      absence: true,
      abbr: '802.11',
      layer: 3,
      virtual: true,
      summary: 'Control frames carry no payload of any kind.',
      offset,
      length: 0,
      fields: [
        field({
          name: 'Why nothing follows',
          value: 'Medium-access control only',
          offset,
          length: 0,
          layer: 3,
          synthetic: true,
          whatText: 'An 802.11 control frame is complete in its header. There is no network, transport or application layer above it, because it is not carrying anyone\'s data — it is arbitrating access to the air.',
          why: 'Wired Ethernet has no equivalent. On a cable, collision detection is handled by the physical layer; on radio, where a transmitter cannot hear itself, that job moves up into frames like these.',
        }),
      ],
    });
    return;
  }
  if (protectedFrame) {
    const remaining = Math.max(0, b.length - cursor);
    ctx.add({
      id: 'wlan-ccmp',
      name: 'Encrypted 802.11 payload',
      abbr: 'CCMP',
      layer: 6,
      summary: `${remaining} bytes encrypted at the link layer`,
      offset: cursor,
      length: remaining,
      fields: [
        field({
          name: 'Protected body',
          value: `${remaining} bytes`,
          offset: cursor,
          length: remaining,
          layer: 6,
          key: 'payload.encrypted',
          why: 'The link layer itself is encrypted, so Layers 3 to 7 are unreadable without the session keys — even for traffic that was never TLS-protected. Note that this protects the frame only between this station and the access point; it is gone the moment the frame reaches the wired network.',
        }),
      ],
    });
    return;
  }
  if (subtype === 4 || subtype === 12) return; // null data frames carry nothing

  dissectLlcSnap(ctx, cursor);
}

/** LLC/SNAP is how a non-Ethernet Layer 2 still names an EtherType. */
function dissectLlcSnap(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 8)) return;
  const dsap = b[offset];
  const ssap = b[offset + 1];
  if (dsap !== 0xaa || ssap !== 0xaa) return;
  const etherType = readU16BE(b, offset + 6);

  ctx.add({
    id: 'llc',
    name: 'Logical Link Control / SNAP',
    abbr: 'LLC',
    layer: 2,
    summary: `SNAP, EtherType ${hex(etherType, 4)}${ETHERTYPES[etherType] ? ` (${ETHERTYPES[etherType]})` : ''}`,
    offset,
    length: 8,
    fields: [
      field({
        name: 'DSAP / SSAP',
        value: `${hex(dsap, 2)} / ${hex(ssap, 2)} (SNAP)`,
        offset,
        length: 2,
        layer: 2,
        whatText: 'Service access points. The value 0xAA in both means a Sub-Network Access Protocol header follows.',
        why: 'An 802.11 header has no EtherType field of its own. LLC/SNAP is the adapter that bolts one on, which is exactly why a Wi-Fi frame carrying IP is eight bytes longer than the equivalent Ethernet frame.',
      }),
      field({ name: 'Control', value: hex(b[offset + 2], 2), offset: offset + 2, length: 1, layer: 2, whatText: '0x03 marks an unnumbered information frame — connectionless, like Ethernet.' }),
      field({ name: 'Organisation Code', value: hex((b[offset + 3] << 16) | (b[offset + 4] << 8) | b[offset + 5], 6), offset: offset + 3, length: 3, layer: 2, whatText: 'Zero means the EtherType that follows is the standard IEEE one.' }),
      field({
        name: 'EtherType',
        value: `${hex(etherType, 4)}${ETHERTYPES[etherType] ? ` (${ETHERTYPES[etherType]})` : ''}`,
        offset: offset + 6,
        length: 2,
        layer: 2,
        key: 'eth.type',
        why: 'Same field, same values, same job as on Ethernet — just carried differently. From here upwards, a wireless packet and a wired one are identical.',
      }),
    ],
    payload: { offset: offset + 8, length: Math.max(0, b.length - offset - 8) },
  });

  if (etherType === 0x0800) dissectIPv4(ctx, offset + 8);
  else if (etherType === 0x86dd) dissectIPv6(ctx, offset + 8);
}

/** Beacon and probe response bodies: fixed parameters then tagged elements. */
function dissectManagementBody(ctx: DissectContext, offset: number, subtype: number, subtypeName: string): void {
  const b = ctx.bytes;
  const fields: Field[] = [];
  let cursor = offset;

  if ((subtype === 8 || subtype === 5) && ctx.has(offset, 12)) {
    const beaconInterval = b[offset + 8] | (b[offset + 9] << 8);
    const capabilities = b[offset + 10] | (b[offset + 11] << 8);
    fields.push(
      field({
        name: 'Timestamp',
        value: 'TSF microseconds',
        offset,
        length: 8,
        layer: 7,
        whatText: 'The access point\'s Timing Synchronisation Function counter.',
        why: 'Every station copies this value into its own clock. It is how a whole cell agrees on when the next beacon is due, and therefore when a sleeping client should wake up.',
      }),
      field({
        name: 'Beacon interval',
        value: `${beaconInterval} time units (${(beaconInterval * 1.024).toFixed(1)} ms)`,
        offset: offset + 8,
        length: 2,
        layer: 7,
        whatText: 'How often the access point transmits a beacon, in 1024-microsecond time units.',
        why: `The usual value of 100 TU is about every 102 milliseconds. Beacons are sent at the slowest supported rate so everyone can hear them, so on a busy 2.4 GHz channel with several networks they can consume a genuinely significant share of the available airtime.`,
      }),
      field({
        name: 'Capability information',
        value: hex(capabilities, 4) + ((capabilities & 0x0010) ? ' (privacy: encryption required)' : ' (open network)'),
        offset: offset + 10,
        length: 2,
        layer: 7,
        whatText: 'Bit flags advertising what the cell supports: infrastructure or ad-hoc, short preamble, short slot time, and whether encryption is required.',
      }),
    );
    cursor = offset + 12;
  }

  // Tagged parameters: one-byte id, one-byte length, then the value.
  let guard = 0;
  const TAGS: Record<number, string> = {
    0: 'SSID',
    1: 'Supported Rates',
    3: 'DS Parameter Set (channel)',
    5: 'Traffic Indication Map',
    42: 'ERP Information',
    45: 'HT Capabilities',
    48: 'RSN Information (WPA2/WPA3)',
    50: 'Extended Supported Rates',
    61: 'HT Operation',
  };

  while (cursor + 2 <= b.length && guard++ < 40) {
    const tag = b[cursor];
    const len = b[cursor + 1];
    if (cursor + 2 + len > b.length) break;
    let value = `${len} bytes`;
    let why: string | undefined;

    if (tag === 0) {
      let ssid = '';
      for (let i = 0; i < len; i++) ssid += String.fromCharCode(b[cursor + 2 + i]);
      value = len === 0 ? '(wildcard / hidden)' : ssid;
      ctx.term(ssid);
      why =
        len === 0
          ? 'An empty SSID in a probe request is a wildcard: "any network, please answer". In a beacon it means the network is hidden — though as you can see, hiding the name in the beacon does nothing to hide the BSSID, the channel, or any of the traffic.'
          : `The network name, sent in clear text in every beacon about ten times a second. There is no version of Wi-Fi where the SSID is confidential.`;
    } else if (tag === 3 && len >= 1) {
      const ch = b[cursor + 2];
      value = `channel ${ch}`;
      why = 'The channel the cell operates on, repeated inside the frame so a station that captured the frame on an overlapping channel still knows where the network really is.';
    } else if (tag === 1 || tag === 50) {
      const rates: string[] = [];
      for (let i = 0; i < len; i++) {
        const r = b[cursor + 2 + i];
        rates.push(`${(r & 0x7f) / 2}${r & 0x80 ? '(B)' : ''}`);
      }
      value = `${rates.join(', ')} Mbit/s`;
      why = 'The data rates this cell supports; the ones marked (B) are "basic" rates that every station must be able to receive. Broadcast and management traffic is sent at the lowest basic rate, so leaving 1 Mbit/s enabled slows the whole cell down.';
    } else if (tag === 48) {
      value = `${len} bytes`;
      why = 'The Robust Security Network element describes which ciphers and authentication methods the network offers — CCMP with 802.1X or a pre-shared key, and on WPA3, SAE. It is how a client knows what kind of handshake to attempt before it associates.';
    }

    fields.push(
      field({
        name: `${TAGS[tag] ?? `Tag ${tag}`}`,
        value,
        offset: cursor,
        length: 2 + len,
        layer: 7,
        whatText: 'A tagged information element: a one-byte identifier, a one-byte length, then the value. 802.11 has extended itself for twenty-five years purely by defining new tag numbers.',
        why,
      }),
    );
    cursor += 2 + len;
  }

  if (fields.length === 0) return;

  ctx.add({
    id: 'wlan-mgt',
    name: `802.11 ${subtypeName} body`,
    abbr: '802.11',
    layer: 7,
    summary: `${fields.length} parameters`,
    offset,
    length: Math.max(0, cursor - offset),
    fields,
  });

  const ssidField = fields.find((f) => f.name === 'SSID');
  if (ssidField) ctx.info = `${subtypeName}, SSID "${ssidField.value}"`;
}

export { frequencyToChannel };
