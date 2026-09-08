/** UDP dissection plus the Layer 5 note that UDP has no session at all. */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { hex, readU16BE } from '../bytes';
import { portName, portRangeNote, serviceSide } from './ports';
import { verifyTransportChecksum } from './tcp';
import { dissectApplication } from './application';

export function dissectUdp(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 8)) {
    ctx.truncated('UDP', offset, 8);
    return;
  }

  const srcPort = readU16BE(b, offset);
  const dstPort = readU16BE(b, offset + 2);
  const length = readU16BE(b, offset + 4);
  const checksum = readU16BE(b, offset + 6);

  ctx.srcPort = srcPort;
  ctx.dstPort = dstPort;
  ctx.term(srcPort, dstPort, 'udp', portName(srcPort)?.toLowerCase(), portName(dstPort)?.toLowerCase());

  const datagramEnd = Math.min(ctx.transportEnd ?? b.length, b.length);
  const declaredPayload = Math.max(0, length - 8);
  const availablePayload = Math.max(0, datagramEnd - (offset + 8));
  const payloadLength = Math.min(declaredPayload, availablePayload);
  const checksumResult = verifyTransportChecksum(ctx, offset, Math.min(length, datagramEnd - offset), 6);

  const fields: Field[] = [
    field({
      name: 'Source Port',
      value: `${srcPort}${portName(srcPort) ? ` (${portName(srcPort)})` : ''}`,
      offset,
      length: 2,
      layer: 4,
      key: 'udp.sport',
      why: portRangeNote(srcPort),
    }),
    field({
      name: 'Destination Port',
      value: `${dstPort}${portName(dstPort) ? ` (${portName(dstPort)})` : ''}`,
      offset: offset + 2,
      length: 2,
      layer: 4,
      key: 'udp.dport',
      why: portRangeNote(dstPort),
    }),
    field({
      name: 'Length',
      value: `${length} bytes (8 header + ${declaredPayload} payload)`,
      offset: offset + 4,
      length: 2,
      layer: 4,
      key: 'udp.length',
      why: 'UDP\'s entire header is these 8 bytes. There is no sequence number, no acknowledgement and no window — which is exactly why it is fast and why anything it carries must handle loss itself.',
      note: declaredPayload > availablePayload ? 'warn' : undefined,
    }),
    field({
      name: 'Checksum',
      value: `${hex(checksum, 4)} ${checksumResult.label}`,
      offset: offset + 6,
      length: 2,
      layer: 4,
      key: 'udp.checksum',
      why: checksumResult.why,
      note: checksumResult.ok === false ? 'warn' : undefined,
    }),
  ];

  ctx.add({
    id: 'udp',
    name: 'User Datagram Protocol',
    abbr: 'UDP',
    layer: 4,
    summary: `${srcPort} -> ${dstPort}, ${declaredPayload} bytes of payload`,
    offset,
    length: 8,
    fields,
    payload: { offset: offset + 8, length: payloadLength },
  });

  ctx.info = `${srcPort} -> ${dstPort} Len=${declaredPayload}`;

  ctx.add({
    id: 'session',
    name: 'Session layer (none — UDP is connectionless)',
    abbr: 'SESSION',
    layer: 5,
    virtual: true,
    summary: 'No transport-provided session; any session state lives in the application protocol.',
    offset,
    length: 0,
    fields: [
      field({
        name: 'Transport session state',
        value: 'None',
        offset,
        length: 0,
        layer: 5,
        synthetic: true,
        whatText:
          'UDP keeps no state between datagrams. There is no handshake, no teardown, and no guarantee that two datagrams from the same host are related at all.',
        why: 'If this conversation needs a session, the application must build one itself — a DNS transaction ID, a DHCP transaction ID, a QUIC connection ID, or an RTP synchronisation source.',
      }),
      field({
        name: 'OSI note',
        value: 'Layer 5 has no header of its own in TCP/IP',
        offset,
        length: 0,
        layer: 5,
        synthetic: true,
        key: 'session.model',
      }),
    ],
  });

  if (payloadLength > 0) {
    dissectApplication(ctx, offset + 8, payloadLength, {
      transport: 'udp',
      servicePort: serviceSide(srcPort, dstPort),
      srcPort,
      dstPort,
    });
  }
}
