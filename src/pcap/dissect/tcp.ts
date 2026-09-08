/**
 * TCP dissection: header, bitwise flag expansion, options, pseudo-header
 * checksum verification, and the Layer 5 commentary that TCP earns by being
 * the thing that actually plays the session role in a TCP/IP stack.
 */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { bitMaskString, hex, hexPreview, internetChecksum, readU16BE, readU32BE } from '../bytes';
import { portName, portRangeNote, serviceSide } from './ports';
import { dissectApplication } from './application';

interface FlagSpec {
  name: string;
  short: string;
  bit: number; // bit index counted from the MSB of the 16-bit flags word
  key: string;
}

const FLAGS: FlagSpec[] = [
  { name: 'Nonce Sum (NS)', short: 'NS', bit: 7, key: 'tcp.flag.ns' },
  { name: 'Congestion Window Reduced (CWR)', short: 'CWR', bit: 8, key: 'tcp.flag.cwr' },
  { name: 'ECN-Echo (ECE)', short: 'ECE', bit: 9, key: 'tcp.flag.ece' },
  { name: 'Urgent (URG)', short: 'URG', bit: 10, key: 'tcp.flag.urg' },
  { name: 'Acknowledgement (ACK)', short: 'ACK', bit: 11, key: 'tcp.flag.ack' },
  { name: 'Push (PSH)', short: 'PSH', bit: 12, key: 'tcp.flag.psh' },
  { name: 'Reset (RST)', short: 'RST', bit: 13, key: 'tcp.flag.rst' },
  { name: 'Synchronise (SYN)', short: 'SYN', bit: 14, key: 'tcp.flag.syn' },
  { name: 'Finish (FIN)', short: 'FIN', bit: 15, key: 'tcp.flag.fin' },
];

/** Explain what this particular flag combination means for the connection. */
function explainFlags(syn: boolean, ack: boolean, fin: boolean, rst: boolean, psh: boolean): string {
  if (rst) {
    return 'RST tears the connection down immediately with no negotiation. You see it when a port is closed, when a host has forgotten the connection (after a reboot or a NAT timeout), or when a firewall or IPS is actively killing the session.';
  }
  if (syn && !ack) {
    return 'SYN set and ACK clear is step 1 of the three-way handshake: the client is opening a connection and announcing its Initial Sequence Number. Nothing has been agreed yet — this is also what a port scanner sends.';
  }
  if (syn && ack) {
    return 'SYN and ACK together is step 2: the server accepts the connection, acknowledges the client\'s ISN, and announces its own. A SYN+ACK is proof the port is open and listening.';
  }
  if (fin && ack) {
    return 'FIN with ACK begins a graceful close of this direction of the connection. TCP closes each direction independently, so the peer can keep sending until it sends its own FIN.';
  }
  if (fin) {
    return 'FIN says "I have no more data to send". The other half of the connection stays open until the peer also sends a FIN.';
  }
  if (ack && psh) {
    return 'ACK with PSH is ordinary data delivery: acknowledge what arrived, and tell the receiving stack to hand this data to the application immediately instead of buffering it.';
  }
  if (ack) {
    return 'A bare ACK. Either step 3 of the handshake (completing the connection), or a pure acknowledgement of data received, or a window update.';
  }
  return 'An unusual flag combination. Packets with no flags, or with impossible combinations like SYN+FIN, are typically scanner or OS-fingerprinting probes rather than real traffic.';
}

export function dissectTcp(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 20)) {
    ctx.truncated('TCP', offset, 20);
    return;
  }

  const srcPort = readU16BE(b, offset);
  const dstPort = readU16BE(b, offset + 2);
  const seq = readU32BE(b, offset + 4);
  const ackNum = readU32BE(b, offset + 8);
  const offsetFlags = readU16BE(b, offset + 12);
  const dataOffset = (offsetFlags >> 12) & 0x0f;
  const headerLength = dataOffset * 4;
  const flagBits = offsetFlags & 0x01ff;
  const window = readU16BE(b, offset + 14);
  const checksum = readU16BE(b, offset + 16);
  const urgentPtr = readU16BE(b, offset + 18);

  const flagSet = (bit: number) => ((offsetFlags >> (15 - bit)) & 1) === 1;
  const syn = flagSet(14);
  const ack = flagSet(11);
  const fin = flagSet(15);
  const rst = flagSet(13);
  const psh = flagSet(12);
  const urg = flagSet(10);

  const flagNames = FLAGS.filter((f) => flagSet(f.bit)).map((f) => f.short);
  const flagLabel = flagNames.length ? flagNames.join(', ') : 'none';

  ctx.srcPort = srcPort;
  ctx.dstPort = dstPort;
  ctx.term(srcPort, dstPort, 'tcp', portName(srcPort)?.toLowerCase(), portName(dstPort)?.toLowerCase(), ...flagNames.map((f) => f.toLowerCase()));

  // Bound the segment by the IP payload, not by the frame: a short frame is
  // padded to 60 bytes by the NIC and that padding is not TCP data.
  const segmentEnd = Math.min(ctx.transportEnd ?? b.length, b.length);
  const payloadStart = offset + headerLength;
  const payloadLength = Math.max(0, segmentEnd - payloadStart);

  const checksumResult = verifyTransportChecksum(ctx, offset, Math.max(0, segmentEnd - offset), 16);

  const fields: Field[] = [
    field({
      name: 'Source Port',
      value: `${srcPort}${portName(srcPort) ? ` (${portName(srcPort)})` : ''}`,
      offset,
      length: 2,
      layer: 4,
      key: 'tcp.sport',
      why: portRangeNote(srcPort),
    }),
    field({
      name: 'Destination Port',
      value: `${dstPort}${portName(dstPort) ? ` (${portName(dstPort)})` : ''}`,
      offset: offset + 2,
      length: 2,
      layer: 4,
      key: 'tcp.dport',
      why: portRangeNote(dstPort),
    }),
    field({
      name: 'Sequence Number',
      value: String(seq),
      offset: offset + 4,
      length: 4,
      layer: 4,
      key: 'tcp.seq',
      why: syn
        ? `Because SYN is set, this is the Initial Sequence Number. It is chosen randomly (here ${seq}) precisely so an off-path attacker cannot guess it and inject data into the stream. The first real data byte will be ${seq + 1 >>> 0}.`
        : `This segment's first payload byte sits at absolute stream position ${seq}. Wireshark normally shows relative numbers; this tool shows the raw value that is genuinely on the wire.`,
    }),
    field({
      name: 'Acknowledgement Number',
      value: ack ? String(ackNum) : `${ackNum} (ignored — ACK flag is clear)`,
      offset: offset + 8,
      length: 4,
      layer: 4,
      key: 'tcp.ack',
      why: ack
        ? `The sender has received every byte up to ${ackNum} - 1 and expects ${ackNum} next. TCP acknowledgements are cumulative, so one ACK covers everything before it.`
        : 'The ACK flag is clear, so this field carries no meaning. That only happens on the very first SYN of a connection.',
    }),
    field({
      name: 'Data Offset (header length)',
      value: `${dataOffset} words = ${headerLength} bytes`,
      offset: offset + 12,
      length: 1,
      bits: { offset: 0, length: 4 },
      layer: 4,
      key: 'tcp.offset',
      why:
        headerLength === 20
          ? 'A 20-byte header means no TCP options are present.'
          : `${headerLength - 20} bytes of TCP options follow the fixed header.`,
    }),
    field({
      name: 'Flags',
      value: `${flagLabel} (${hex(flagBits, 3)})`,
      offset: offset + 12,
      length: 2,
      bits: { offset: 7, length: 9 },
      layer: 4,
      key: 'tcp.flags',
      why: explainFlags(syn, ack, fin, rst, psh),
      note: rst ? 'warn' : undefined,
      children: FLAGS.map((f) =>
        field({
          name: f.name,
          value: `${flagSet(f.bit) ? '1 = set' : '0 = not set'}   ${bitMaskString(offsetFlags, 16, f.bit, 1)}`,
          offset: offset + 12,
          length: 2,
          bits: { offset: f.bit, length: 1 },
          layer: 4,
          key: f.key,
        }),
      ),
    }),
    field({
      name: 'Window Size',
      value: String(window),
      offset: offset + 14,
      length: 2,
      layer: 4,
      key: 'tcp.window',
      why:
        window === 0
          ? 'A zero window is flow control in action: the receiver\'s buffer is full and the sender must stop until a window update arrives. Persistent zero windows mean a slow or stalled application, not a slow network.'
          : `The sender can accept ${window} more bytes before it must be acknowledged — unless window scaling was negotiated in the handshake, in which case multiply by the scale factor. This is receiver-side flow control, entirely separate from congestion control.`,
      note: window === 0 ? 'warn' : undefined,
    }),
    field({
      name: 'Checksum',
      value: `${hex(checksum, 4)} ${checksumResult.label}`,
      offset: offset + 16,
      length: 2,
      layer: 4,
      key: 'tcp.checksum',
      why: checksumResult.why,
      note: checksumResult.ok === false ? 'warn' : undefined,
    }),
    field({
      name: 'Urgent Pointer',
      value: urg ? String(urgentPtr) : `${urgentPtr} (ignored — URG flag is clear)`,
      offset: offset + 18,
      length: 2,
      layer: 4,
      key: 'tcp.urgptr',
    }),
  ];

  if (headerLength > 20 && ctx.has(offset + 20, headerLength - 20)) {
    const optionFields = parseTcpOptions(ctx, offset + 20, headerLength - 20);
    fields.push(
      field({
        name: 'Options',
        value: `${headerLength - 20} bytes`,
        offset: offset + 20,
        length: headerLength - 20,
        layer: 4,
        key: 'tcp.options',
        children: optionFields,
      }),
    );
  }

  ctx.add({
    id: 'tcp',
    name: 'Transmission Control Protocol',
    abbr: 'TCP',
    layer: 4,
    summary: `${srcPort} -> ${dstPort} [${flagLabel}] seq=${seq}${ack ? ` ack=${ackNum}` : ''} win=${window} len=${payloadLength}`,
    offset,
    length: headerLength,
    fields,
    payload: { offset: payloadStart, length: payloadLength },
  });

  ctx.info =
    `${srcPort} -> ${dstPort} [${flagLabel}] Seq=${seq}` +
    (ack ? ` Ack=${ackNum}` : '') +
    ` Win=${window} Len=${payloadLength}`;

  addTcpSessionLayer(ctx, offset, { srcPort, dstPort, syn, ack, fin, rst, seq, ackNum });

  if (payloadLength > 0) {
    dissectApplication(ctx, payloadStart, payloadLength, {
      transport: 'tcp',
      servicePort: serviceSide(srcPort, dstPort),
      srcPort,
      dstPort,
    });
  }
}

/**
 * The Layer 5 entry for a TCP connection.
 *
 * TCP/IP has no separate session protocol, so rather than leaving Layer 5
 * blank we explain which TCP mechanism is doing the session layer's job for
 * this specific packet.
 */
function addTcpSessionLayer(
  ctx: DissectContext,
  offset: number,
  s: { srcPort: number; dstPort: number; syn: boolean; ack: boolean; fin: boolean; rst: boolean; seq: number; ackNum: number },
): void {
  let state: string;
  let why: string;
  if (s.syn && !s.ack) {
    state = 'Session establishment requested (SYN)';
    why = 'Step 1 of 3. The client is asking to open a session. Nothing above this layer can happen until the handshake completes.';
  } else if (s.syn && s.ack) {
    state = 'Session establishment accepted (SYN, ACK)';
    why = 'Step 2 of 3. The server agrees to the session and synchronises its own sequence space.';
  } else if (s.fin) {
    state = 'Session teardown (FIN)';
    why = 'One direction of the session is being closed gracefully. Because TCP connections are full-duplex, the session is not fully over until both directions have sent and acknowledged a FIN.';
  } else if (s.rst) {
    state = 'Session aborted (RST)';
    why = 'The session is being destroyed without an orderly close. Any unacknowledged data is lost.';
  } else if (s.ack && s.seq !== 0) {
    state = 'Session established — data transfer';
    why = 'The handshake is done, so this segment belongs to an established session. From here on the "session" is simply the four-tuple state held in both hosts\' TCP tables.';
  } else {
    state = 'Session state unclear from this segment alone';
    why = 'Judging session state from a single segment is unreliable; follow the whole conversation in the packet list.';
  }

  const tuple = `${ctx.source}:${s.srcPort} <-> ${ctx.destination}:${s.dstPort}`;

  ctx.add({
    id: 'session',
    name: 'Session layer (provided by TCP)',
    abbr: 'SESSION',
    layer: 5,
    virtual: true,
    summary: state,
    offset,
    length: 0,
    fields: [
      field({
        name: 'Session identifier (four-tuple)',
        value: tuple,
        offset,
        length: 4,
        layer: 5,
        synthetic: true,
        key: 'session.tcp',
        why: `Both hosts keep a Transmission Control Block keyed on exactly this four-tuple. That block — not any header on the wire — is the session.`,
      }),
      field({
        name: 'Dialogue state',
        value: state,
        offset,
        length: 2,
        layer: 5,
        synthetic: true,
        whatText:
          'Which part of the session lifecycle — establishment, data transfer, or termination — this segment belongs to.',
        why,
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
}

/** Verify a TCP or UDP checksum, including the IPv4/IPv6 pseudo-header. */
export function verifyTransportChecksum(
  ctx: DissectContext,
  offset: number,
  length: number,
  checksumFieldOffset: number,
): { ok: boolean | null; label: string; why: string } {
  const stored = readU16BE(ctx.bytes, offset + checksumFieldOffset);
  if (!ctx.ipSrcBytes || !ctx.ipDstBytes || ctx.ipProtocol === undefined) {
    return {
      ok: null,
      label: '(not verified)',
      why: 'The checksum could not be verified because the IP addresses needed for the pseudo-header are not available.',
    };
  }
  if (stored === 0 && ctx.ipVersion === 4) {
    return {
      ok: null,
      label: '(not computed)',
      why: 'A zero checksum in IPv4 UDP means the sender chose not to compute one, which the standard permits. IPv6 forbids it.',
    };
  }
  if (offset + length > ctx.bytes.length) {
    return {
      ok: null,
      label: '(not verified — packet truncated)',
      why: 'The packet was sliced by the capture snapshot length, so there are not enough bytes to recompute the checksum.',
    };
  }

  const pseudo = new Uint8Array(ctx.ipVersion === 6 ? 40 : 12);
  if (ctx.ipVersion === 6) {
    pseudo.set(ctx.ipSrcBytes, 0);
    pseudo.set(ctx.ipDstBytes, 16);
    pseudo[32] = (length >>> 24) & 0xff;
    pseudo[33] = (length >>> 16) & 0xff;
    pseudo[34] = (length >>> 8) & 0xff;
    pseudo[35] = length & 0xff;
    pseudo[39] = ctx.ipProtocol;
  } else {
    pseudo.set(ctx.ipSrcBytes, 0);
    pseudo.set(ctx.ipDstBytes, 4);
    pseudo[8] = 0;
    pseudo[9] = ctx.ipProtocol;
    pseudo[10] = (length >>> 8) & 0xff;
    pseudo[11] = length & 0xff;
  }

  const body = ctx.bytes.subarray(offset, offset + length);
  const computed = internetChecksum([pseudo, body], {
    start: pseudo.length + checksumFieldOffset,
    length: 2,
  });
  const ok = computed === stored;
  return {
    ok,
    label: ok ? '(valid)' : `(INVALID — computed ${hex(computed, 4)})`,
    why: ok
      ? 'Verified. The checksum covers the header, the payload, and a pseudo-header made of the source and destination IP addresses, the protocol number and the length — which is how the transport layer detects a packet that was delivered to the wrong host.'
      : 'The checksum does not match. Before concluding the packet is corrupt, remember that captures taken on the transmitting host almost always show bad transport checksums, because modern NICs compute them in hardware after the capture point (checksum offload).',
  };
}

const TCP_OPTIONS: Record<number, string> = {
  0: 'End of Option List',
  1: 'No-Operation',
  2: 'Maximum Segment Size',
  3: 'Window Scale',
  4: 'SACK Permitted',
  5: 'SACK',
  8: 'Timestamps',
  28: 'User Timeout',
  29: 'TCP Authentication Option',
  34: 'TCP Fast Open Cookie',
};

function parseTcpOptions(ctx: DissectContext, offset: number, length: number): Field[] {
  const out: Field[] = [];
  const b = ctx.bytes;
  const end = offset + length;
  let o = offset;
  let guard = 0;
  while (o < end && guard++ < 64) {
    const kind = b[o];
    if (kind === 0) {
      out.push(field({ name: 'End of Option List', value: 'EOL', offset: o, length: 1, layer: 4, key: 'tcp.opt.eol' }));
      break;
    }
    if (kind === 1) {
      out.push(field({ name: 'No-Operation', value: 'NOP', offset: o, length: 1, layer: 4, key: 'tcp.opt.nop' }));
      o += 1;
      continue;
    }
    const len = b[o + 1] ?? 0;
    if (len < 2 || o + len > end) {
      ctx.warn('Malformed TCP option length; stopping option parsing.');
      break;
    }
    const name = TCP_OPTIONS[kind] ?? `Option kind ${kind}`;
    let value = hexPreview(b, o + 2, len - 2);
    let why: string | undefined;
    let key: string | undefined;

    switch (kind) {
      case 2: {
        const mss = readU16BE(b, o + 2);
        value = `${mss} bytes`;
        key = 'tcp.opt.mss';
        why =
          mss === 1460
            ? 'MSS 1460 is the classic value: a 1500-byte Ethernet MTU minus 20 bytes of IPv4 header and 20 bytes of TCP header.'
            : `An MSS of ${mss} suggests a path MTU of about ${mss + 40} bytes. Values well below 1460 usually mean a tunnel (PPPoE, VPN or GRE) is eating header space.`;
        break;
      }
      case 3: {
        const shift = b[o + 2];
        value = `shift ${shift} (multiply window by ${2 ** shift})`;
        key = 'tcp.opt.wscale';
        why = `Every advertised window in this direction must be multiplied by ${2 ** shift}, giving a maximum window of ${(65535 * 2 ** shift / 1024).toFixed(0)} KiB. Without this option TCP could never fill a modern high-bandwidth, high-latency path.`;
        break;
      }
      case 4:
        value = 'permitted';
        key = 'tcp.opt.sackperm';
        why = 'Both ends must send this in the handshake for selective acknowledgement to be usable later.';
        break;
      case 5: {
        const blocks: string[] = [];
        for (let i = o + 2; i + 8 <= o + len; i += 8) {
          blocks.push(`${readU32BE(b, i)}-${readU32BE(b, i + 4)}`);
        }
        value = blocks.join(', ');
        key = 'tcp.opt.sack';
        why = 'These byte ranges arrived out of order. The sender can now retransmit only the missing hole instead of everything after it.';
        break;
      }
      case 8: {
        const tsval = readU32BE(b, o + 2);
        const tsecr = readU32BE(b, o + 6);
        value = `TSval ${tsval}, TSecr ${tsecr}`;
        key = 'tcp.opt.ts';
        why = 'The peer echoes TSval back as TSecr, giving an accurate round-trip time measurement on every segment rather than once per window.';
        break;
      }
      default:
        break;
    }

    out.push(field({ name, value, offset: o, length: len, layer: 4, key, why, whatText: key ? undefined : 'A TCP option carried in the variable part of the header.' }));
    o += len;
  }
  return out;
}
