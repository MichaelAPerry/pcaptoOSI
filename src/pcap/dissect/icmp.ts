/** ICMP and ICMPv6 dissection. */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { asciiOf, hex, hexPreview, internetChecksum, readU16BE } from '../bytes';

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo Reply',
  3: 'Destination Unreachable',
  4: 'Source Quench (deprecated)',
  5: 'Redirect',
  8: 'Echo Request',
  9: 'Router Advertisement',
  10: 'Router Solicitation',
  11: 'Time Exceeded',
  12: 'Parameter Problem',
  13: 'Timestamp Request',
  14: 'Timestamp Reply',
};

const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination Unreachable',
  2: 'Packet Too Big',
  3: 'Time Exceeded',
  4: 'Parameter Problem',
  128: 'Echo Request',
  129: 'Echo Reply',
  133: 'Router Solicitation',
  134: 'Router Advertisement',
  135: 'Neighbour Solicitation',
  136: 'Neighbour Advertisement',
  137: 'Redirect',
};

const UNREACHABLE_CODES: Record<number, string> = {
  0: 'Network unreachable',
  1: 'Host unreachable',
  2: 'Protocol unreachable',
  3: 'Port unreachable',
  4: 'Fragmentation needed but DF set',
  9: 'Network administratively prohibited',
  10: 'Host administratively prohibited',
  13: 'Communication administratively filtered',
};

const TIME_EXCEEDED_CODES: Record<number, string> = {
  0: 'TTL expired in transit',
  1: 'Fragment reassembly time exceeded',
};

function describeType(type: number, code: number, v6: boolean): string {
  if (!v6) {
    switch (type) {
      case 8:
        return 'An Echo Request — a ping. The receiver is expected to copy the identifier, sequence number and payload into an Echo Reply. Ping is the simplest possible test that Layer 3 connectivity exists in both directions.';
      case 0:
        return 'An Echo Reply. Its arrival proves the path works in both directions, and the round-trip time is the difference between this packet\'s timestamp and the matching request\'s.';
      case 3:
        return code === 4
          ? 'Fragmentation Needed: a router had to forward this packet over a link with a smaller MTU, but Don\'t Fragment was set. This message carries the next-hop MTU and is the engine of Path MTU Discovery. Firewalls that block it cause the classic "small pages load, large downloads hang" failure.'
          : `Destination Unreachable (${UNREACHABLE_CODES[code] ?? `code ${code}`}). A router or the destination host itself is telling the sender the packet could not be delivered. Code 3, port unreachable, is also how traceroute over UDP knows it has arrived.`;
      case 11:
        return `Time Exceeded (${TIME_EXCEEDED_CODES[code] ?? `code ${code}`}). The TTL hit zero and a router discarded the packet, announcing itself in the process. Traceroute works by deliberately provoking exactly this message with increasing TTLs.`;
      case 5:
        return 'Redirect: a router is telling the host there is a better first hop for this destination on the same segment. Frequently disabled, because it is also an attack vector.';
      default:
        return 'An ICMP control message. ICMP is not a transport for user data — it exists so that the network layer can report on itself.';
    }
  }
  switch (type) {
    case 128:
      return 'ICMPv6 Echo Request — ping6.';
    case 129:
      return 'ICMPv6 Echo Reply.';
    case 135:
      return 'Neighbour Solicitation: the IPv6 replacement for an ARP request. Instead of broadcasting, it is sent to the solicited-node multicast group, so only a handful of hosts are ever interrupted.';
    case 136:
      return 'Neighbour Advertisement: the IPv6 answer to a Neighbour Solicitation, carrying the target\'s link-layer address.';
    case 134:
      return 'Router Advertisement: how IPv6 hosts learn their prefix and default gateway, usually without any DHCP server at all (SLAAC).';
    case 2:
      return 'Packet Too Big. IPv6 routers never fragment, so this message is mandatory for Path MTU Discovery to work at all.';
    default:
      return 'An ICMPv6 control message. ICMPv6 absorbed the jobs ARP and IGMP do in IPv4, which is why blocking it wholesale breaks IPv6 networks.';
  }
}

export function dissectIcmp(ctx: DissectContext, offset: number, v6: boolean): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 4)) {
    ctx.truncated(v6 ? 'ICMPv6' : 'ICMP', offset, 4);
    return;
  }

  const end = Math.min(ctx.transportEnd ?? b.length, b.length);
  const type = b[offset];
  const code = b[offset + 1];
  const checksum = readU16BE(b, offset + 2);
  const table = v6 ? ICMP6_TYPES : ICMP_TYPES;
  const typeName = table[type] ?? `type ${type}`;
  const isEcho = v6 ? type === 128 || type === 129 : type === 8 || type === 0;

  ctx.term(v6 ? 'icmpv6' : 'icmp', typeName.toLowerCase());

  const fields: Field[] = [
    field({
      name: 'Type',
      value: `${type} (${typeName})`,
      offset,
      length: 1,
      layer: 4,
      key: v6 ? 'icmp6.type' : 'icmp.type',
      why: describeType(type, code, v6),
    }),
    field({
      name: 'Code',
      value: `${code}${type === 3 && !v6 ? ` (${UNREACHABLE_CODES[code] ?? 'unassigned'})` : type === 11 && !v6 ? ` (${TIME_EXCEEDED_CODES[code] ?? 'unassigned'})` : ''}`,
      offset: offset + 1,
      length: 1,
      layer: 4,
      key: 'icmp.code',
    }),
  ];

  // ICMPv6 checksums include the IPv6 pseudo-header; plain ICMP does not.
  let checksumNote = '';
  if (!v6) {
    const computed = internetChecksum([b.subarray(offset, end)], { start: 2, length: 2 });
    checksumNote = computed === checksum ? ' (valid)' : ` (INVALID — computed ${hex(computed, 4)})`;
  }
  fields.push(
    field({
      name: 'Checksum',
      value: `${hex(checksum, 4)}${checksumNote}`,
      offset: offset + 2,
      length: 2,
      layer: 4,
      key: 'icmp.checksum',
      why: v6
        ? 'ICMPv6 checksums cover an IPv6 pseudo-header as well as the message, unlike ICMP for IPv4.'
        : undefined,
      note: checksumNote.includes('INVALID') ? 'warn' : undefined,
    }),
  );

  let summary = typeName;
  let echoPayload: { offset: number; length: number } | undefined;
  if (isEcho && ctx.has(offset + 4, 4)) {
    const id = readU16BE(b, offset + 4);
    const seq = readU16BE(b, offset + 6);
    const dataOffset = offset + 8;
    const dataLength = Math.max(0, end - dataOffset);
    summary = `${typeName} id=${id} seq=${seq}`;
    ctx.term(`seq${seq}`);

    fields.push(
      field({
        name: 'Identifier',
        value: `${id} (${hex(id, 4)})`,
        offset: offset + 4,
        length: 2,
        layer: 4,
        key: 'icmp.id',
        why: 'The replying host must copy this value back unchanged, which is how a ping tool matches replies to the requests it sent. A NAT device rewrites it, using it as a pseudo-port to demultiplex ICMP through a single public address.',
      }),
      field({
        name: 'Sequence Number',
        value: String(seq),
        offset: offset + 6,
        length: 2,
        layer: 4,
        key: 'icmp.seq',
        why: `This is ping number ${seq} of the run. A gap in the sequence numbers of the replies is packet loss; replies arriving out of order mean the path is reordering traffic.`,
      }),
    );

    if (dataLength > 0) {
      echoPayload = { offset: dataOffset, length: dataLength };
      fields.push(
        field({
          name: 'Payload data',
          value: `${dataLength} bytes: ${asciiOf(b, dataOffset, Math.min(dataLength, 32))}`,
          offset: dataOffset,
          length: dataLength,
          layer: 7,
          key: 'icmp.data',
          why: 'The contents are arbitrary — Linux ping fills the first 8 bytes with a timestamp and the rest with an incrementing pattern, Windows uses the alphabet. Because the responder must echo it verbatim, this field is a favourite covert channel for data exfiltration.',
        }),
      );
    }
  } else if (!isEcho && ctx.has(offset + 8, 20)) {
    // Error messages quote the packet that caused them.
    fields.push(
      field({
        name: 'Quoted original packet',
        value: hexPreview(b, offset + 8, Math.min(28, end - offset - 8)),
        offset: offset + 8,
        length: Math.max(0, Math.min(28, end - offset - 8)),
        layer: 7,
        whatText:
          'Every ICMP error message quotes the beginning of the packet that caused it — at minimum the IP header plus the first 8 bytes of the transport header.',
        why: 'Those 8 quoted bytes contain the source and destination ports, which is what lets the sending host attribute the error to one specific connection rather than to the host as a whole.',
      }),
    );
  }

  ctx.add({
    id: v6 ? 'icmpv6' : 'icmp',
    name: v6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
    abbr: v6 ? 'ICMPv6' : 'ICMP',
    layer: 4,
    summary,
    offset,
    length: Math.max(4, Math.min(8, end - offset)),
    fields,
    payload: echoPayload,
  });

  ctx.info = `${summary}`;

  ctx.add({
    id: 'session',
    name: 'Session layer (not applicable)',
    abbr: 'SESSION',
    layer: 5,
    virtual: true,
    summary: 'ICMP has no session concept; the identifier field is the only correlation mechanism.',
    offset,
    length: 0,
    fields: [
      field({
        name: 'Correlation',
        value: isEcho ? 'Identifier + sequence number' : 'Quoted packet header',
        offset,
        length: 0,
        layer: 5,
        synthetic: true,
        whatText:
          'ICMP is a network-layer control protocol. It does not establish sessions, and it is not carried over TCP or UDP — it sits directly inside IP as protocol number 1.',
        why: 'This is a good example of the model not being a perfect fit for reality: ICMP is usually taught as Layer 3, yet it is encapsulated in IP exactly the way a Layer 4 protocol would be. This tool lists it at Layer 4 because that is where it sits structurally in the frame.',
      }),
    ],
  });
}
