/**
 * The OSI mapping layer.
 *
 * The dissectors tag every field with the OSI layer it belongs to. This module
 * turns that flat tagging into the seven-layer view the UI renders, and is
 * also where the honest explanations live for the layers that TCP/IP does not
 * implement separately.
 */

import type { DissectedPacket, Field, OsiLayer, ProtocolLayer } from './types';
import { LAYER_NAMES, LAYER_PDU } from './types';

export interface ByteRange {
  offset: number;
  length: number;
}

export interface LayerView {
  layer: OsiLayer;
  name: string;
  pdu: string;
  /** Protocol headers that contribute to this layer. */
  protocols: ProtocolLayer[];
  /** Fields tagged with this layer, nested structure preserved. */
  fields: Field[];
  /** Byte ranges belonging to this layer, for hex highlighting. */
  ranges: ByteRange[];
  /** Whether anything real was found at this layer. */
  present: boolean;
  /** Comma-separated protocol names for the layer header. */
  label: string;
  /** Explanation shown when the layer has no protocol of its own. */
  absenceNote?: string;
}

const ABSENCE_NOTES: Partial<Record<OsiLayer, string>> = {
  3: 'No network-layer header in this frame. That is normal for protocols that stop at Layer 2, such as ARP, STP and LLDP — they are addressed to the local segment only and can never be routed.',
  4: 'No transport-layer header in this frame, so there are no ports and no notion of a connection. That is normal for anything that stops below the transport layer — ARP, STP and LLDP among them.',
  5: 'The TCP/IP stack has no dedicated session-layer protocol. When a capture shows nothing here, session duties are either absent (a single stateless datagram) or handled entirely inside the application protocol.',
  6: 'No explicit presentation-layer negotiation in this frame. In TCP/IP, Layer 6 duties appear as TLS records, MIME types, content encodings or a protocol-specific binary format — none of which are present here.',
  7: 'No application data in this frame. Some frames are pure protocol machinery: a bare TCP SYN, ACK or FIN exists only to drive the transport state machine, and a protocol such as ARP never reaches this high in the stack at all.',
};

/** Collect fields tagged with `layer`, keeping nested structure intact. */
function collectFields(fields: Field[], layer: OsiLayer, out: Field[]): void {
  for (const f of fields) {
    if (f.layer === layer) {
      out.push(f);
    } else if (f.children?.length) {
      collectFields(f.children, layer, out);
    }
  }
}

function mergeRanges(ranges: ByteRange[]): ByteRange[] {
  const valid = ranges.filter((r) => r.length > 0).sort((a, b) => a.offset - b.offset);
  const merged: ByteRange[] = [];
  for (const r of valid) {
    const last = merged[merged.length - 1];
    if (last && r.offset <= last.offset + last.length) {
      last.length = Math.max(last.length, r.offset + r.length - last.offset);
    } else {
      merged.push({ ...r });
    }
  }
  return merged;
}

export function buildLayerViews(packet: DissectedPacket): LayerView[] {
  const views: LayerView[] = [];

  for (let n = 1 as OsiLayer; n <= 7; n = (n + 1) as OsiLayer) {
    const protocols = packet.protocols.filter(
      (p) => p.layer === n || p.alsoLayers?.includes(n),
    );
    const fields: Field[] = [];
    for (const p of packet.protocols) collectFields(p.fields, n, fields);

    // Fields contributed purely to explain an absence do not make a layer present.
    const absenceFields: Field[] = [];
    for (const p of packet.protocols) {
      if (p.absence) collectFields(p.fields, n, absenceFields);
    }
    const absenceIds = new Set(absenceFields.map((f) => f.id));

    const realRanges = mergeRanges(
      protocols.filter((p) => !p.virtual && p.length > 0).map((p) => ({ offset: p.offset, length: p.length })),
    );

    // Layer 1 normally owns no bytes of its own, so it claims the whole frame:
    // those are, after all, the bits that were on the medium. The exception is
    // a monitor-mode Wi-Fi capture, where radiotap really is a Layer 1 header
    // occupying real bytes — then Layer 1 highlights precisely those.
    const ranges: ByteRange[] =
      n === 1 && realRanges.length === 0 ? [{ offset: 0, length: packet.bytes.length }] : realRanges;

    // Layers 5-7 often have no header of their own; fall back to the byte
    // ranges of the fields that were tagged with the layer.
    if (ranges.length === 0 && n >= 5) {
      const fieldRanges = fields
        .filter((f) => f.length > 0 && !f.synthetic)
        .map((f) => ({ offset: f.offset, length: f.length }));
      ranges.push(...mergeRanges(fieldRanges));
    }

    const realProtocols = protocols.filter((p) => !p.virtual);
    const absenceProtocols = protocols.filter((p) => p.absence);
    const present =
      realProtocols.length > 0 || fields.some((f) => !absenceIds.has(f.id));

    const label =
      realProtocols.length > 0
        ? realProtocols.map((p) => p.name).join(', ')
        : protocols.length > 0
          ? protocols.map((p) => p.name).join(', ')
          : 'Not present in this frame';


    views.push({
      layer: n,
      name: LAYER_NAMES[n],
      pdu: LAYER_PDU[n],
      protocols,
      fields,
      ranges,
      present,
      label,
      // A protocol-specific explanation always beats the generic one.
      absenceNote: present || absenceProtocols.length > 0 ? undefined : ABSENCE_NOTES[n],
    });
  }

  return views;
}

/** One box in the encapsulation (Russian-doll) diagram. */
export interface EncapsulationBox {
  id: string;
  name: string;
  abbr: string;
  layer: OsiLayer;
  pdu: string;
  /** The header bytes this protocol adds. */
  header: ByteRange;
  /** Everything this protocol wraps (its payload), if any. */
  payload?: ByteRange;
  summary: string;
  /** How the outgoing (Tx) side describes what this layer does. */
  encapNote: string;
  /** How the incoming (Rx) side describes it. */
  decapNote: string;
}

const ENCAP_NOTES: Record<number, { tx: string; rx: string }> = {
  2: {
    tx: 'The data link layer frames the packet for one specific physical hop: it writes the destination MAC of the next device on this segment, its own MAC, and the EtherType that says what is inside. A trailer with the frame check sequence is added by the NIC.',
    rx: 'The NIC checks the frame check sequence, confirms the destination MAC is its own (or a broadcast/multicast it has joined), strips the frame header and passes the payload up based on the EtherType.',
  },
  3: {
    tx: 'The network layer adds source and destination IP addresses — the ones that survive every hop — plus a TTL to stop routing loops, and a protocol number naming the transport above.',
    rx: 'The host confirms the destination address is its own, verifies the header checksum, reassembles fragments if needed, and hands the payload to the transport protocol named in the Protocol field.',
  },
  4: {
    tx: 'The transport layer adds ports so the receiving host knows which process gets the data, plus (for TCP) sequence numbers, acknowledgements and a window for reliability and flow control.',
    rx: 'The stack finds the socket matching the four-tuple, verifies the checksum, puts segments back in order, acknowledges them, and delivers a clean byte stream to the application.',
  },
  5: {
    tx: 'The session layer establishes and identifies the dialogue. In TCP/IP this means the TCP connection itself, a TLS session, or an identifier the application invented, such as a DNS transaction ID or a cookie.',
    rx: 'The receiver matches this message to an existing dialogue — a TCP control block, a TLS session, a pending DNS transaction — and rejects anything that does not belong to one.',
  },
  6: {
    tx: 'The presentation layer decides how the data is represented on the wire: encryption via TLS, compression via gzip, character encoding, and structure via ASN.1, JSON or a protocol-specific binary format.',
    rx: 'The receiver reverses those transforms — decrypt, decompress, decode the character set and parse the structure — turning wire bytes back into values the application can use.',
  },
  7: {
    tx: 'The application layer is where the actual message begins: an HTTP request, a DNS question, a DHCP offer. Everything below exists only to deliver these bytes intact.',
    rx: 'The application receives exactly the bytes that were sent, with no knowledge of the MAC rewrites, routing decisions, retransmissions or encryption that got them here.',
  },
};

/**
 * Overrides for protocols the generic per-layer wording does not fit.
 *
 * ICMP is the important one: it sits where a transport header would, but it
 * has no ports and no connection, so the standard Layer 4 story would be
 * actively misleading.
 */
const PROTOCOL_NOTES: Record<string, { tx: string; rx: string }> = {
  icmp: {
    tx: 'ICMP is not a transport for user data. It rides directly inside IP as protocol number 1 so the network layer can report on itself, and it adds only a type, a code and a checksum — no ports, no connection, no ordering.',
    rx: 'The host verifies the checksum and reads the type and code. An echo request is answered immediately by the kernel; an error message is matched to a connection using the original packet header quoted inside it.',
  },
  icmpv6: {
    tx: 'ICMPv6 rides directly inside IPv6 as next header 58. It carries no ports and no connection state, and it absorbed the jobs ARP and IGMP do in IPv4 — which is why blocking it wholesale breaks IPv6 entirely.',
    rx: 'The host verifies the checksum (which covers an IPv6 pseudo-header) and acts on the type: answer an echo, update the neighbour cache, or adjust the path MTU.',
  },
  arp: {
    tx: 'ARP is not wrapped in anything above Ethernet. It gets its own EtherType, 0x0806, and its message is the whole payload of the frame — which is exactly why an ARP request cannot leave the local segment.',
    rx: 'Every station on the segment receives the broadcast, compares the target IP with its own, and only the owner answers. Everyone else may still cache the sender\'s mapping.',
  },
  tls: {
    tx: 'TLS wraps the application\'s bytes in records: a content type, a version and a length, then the encrypted and authenticated payload. Once the handshake completes, nothing above this point is visible on the wire.',
    rx: 'The receiver reassembles the record from the TCP stream, decrypts and authenticates it, and hands the plaintext to whichever protocol ALPN agreed on.',
  },
  udp: {
    tx: 'UDP adds ports and a length, and nothing else. No sequence numbers, no acknowledgements, no window — if the application needs reliability or ordering, it has to build them itself.',
    rx: 'The host checks the destination port for a listening socket, verifies the checksum, and hands the datagram over whole. A datagram either arrives complete or not at all.',
  },
};

export function buildEncapsulation(packet: DissectedPacket): EncapsulationBox[] {
  return packet.protocols
    // Trailers (Ethernet padding) are real bytes but not a wrapper around
    // anything, so they would nest nonsensically inside the diagram.
    .filter((p) => !p.virtual && !p.trailer && p.length > 0)
    .map((p) => ({
      id: p.id,
      name: p.name,
      abbr: p.abbr,
      layer: p.layer,
      pdu: LAYER_PDU[p.layer],
      header: { offset: p.offset, length: p.length },
      payload: p.payload && p.payload.length > 0 ? p.payload : undefined,
      summary: p.summary,
      encapNote: PROTOCOL_NOTES[p.id]?.tx ?? ENCAP_NOTES[p.layer]?.tx ?? '',
      decapNote: PROTOCOL_NOTES[p.id]?.rx ?? ENCAP_NOTES[p.layer]?.rx ?? '',
    }));
}

/** Flatten a field tree, used by the hex viewer's hover index. */
export function flattenFields(fields: Field[], out: Field[] = []): Field[] {
  for (const f of fields) {
    out.push(f);
    if (f.children) flattenFields(f.children, out);
  }
  return out;
}
