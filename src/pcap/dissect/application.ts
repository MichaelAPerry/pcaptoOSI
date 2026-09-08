/**
 * Application-layer dispatcher.
 *
 * Routing is by well-known port first, then by content sniffing, then a
 * readable raw-bytes fallback. The fallback matters pedagogically: a student
 * should never hit a dead end, and "here are the bytes, here is what we can
 * still infer" is a real analyst's answer.
 */

import { DissectContext, field } from './context';
import { asciiOf, hexPreview, readU16BE, utf8Of } from '../bytes';
import { dissectDns } from './dns';
import { dissectHttp, looksLikeHttp } from './http';
import { dissectTls, looksLikeTls } from './tls';
import { dissectDhcp, looksLikeDhcp } from './dhcp';
import { portName } from './ports';

export interface AppContext {
  transport: 'tcp' | 'udp';
  servicePort: number;
  srcPort: number;
  dstPort: number;
}

export function dissectApplication(ctx: DissectContext, offset: number, length: number, app: AppContext): void {
  const { transport, servicePort, srcPort, dstPort } = app;
  const ports = [srcPort, dstPort];

  // --- port-directed dissection -------------------------------------------
  if (transport === 'udp' && (ports.includes(53) || servicePort === 53)) {
    dissectDns(ctx, offset, length, false);
    return;
  }
  if (transport === 'udp' && ports.includes(5353)) {
    dissectDns(ctx, offset, length, false, 'mDNS');
    return;
  }
  if (transport === 'udp' && (ports.includes(67) || ports.includes(68))) {
    if (looksLikeDhcp(ctx, offset, length)) {
      dissectDhcp(ctx, offset, length);
      return;
    }
  }
  if (transport === 'tcp' && ports.includes(53) && length > 2) {
    // DNS over TCP is length-prefixed with a 2-byte big-endian count.
    const declared = readU16BE(ctx.bytes, offset);
    ctx.add({
      id: 'dns-len',
      name: 'DNS-over-TCP length prefix',
      abbr: 'DNS',
      layer: 7,
      summary: `${declared} bytes of DNS message follow`,
      offset,
      length: 2,
      fields: [
        field({
          name: 'Message length',
          value: String(declared),
          offset,
          length: 2,
          layer: 7,
          whatText:
            'TCP delivers a byte stream with no message boundaries, so DNS over TCP has to add its own two-byte length prefix. UDP needs no such thing because a datagram is already a message.',
          why: 'This is a neat illustration of what the transport layer does and does not give you: reliability and ordering, but not framing.',
        }),
      ],
    });
    dissectDns(ctx, offset + 2, Math.min(declared, length - 2), true);
    return;
  }

  // --- content sniffing ----------------------------------------------------
  if (looksLikeTls(ctx, offset, length)) {
    dissectTls(ctx, offset, length);
    return;
  }
  if (looksLikeHttp(ctx, offset, length)) {
    dissectHttp(ctx, offset, length);
    return;
  }
  if (transport === 'udp' && looksLikeDhcp(ctx, offset, length)) {
    dissectDhcp(ctx, offset, length);
    return;
  }

  addGenericPayload(ctx, offset, length, app);
}

/**
 * The honest fallback: show the bytes, say what can still be inferred, and
 * explain why Layers 5-7 may be opaque.
 */
function addGenericPayload(ctx: DissectContext, offset: number, length: number, app: AppContext): void {
  const service = portName(app.servicePort);
  const text = utf8Of(ctx.bytes, offset, Math.min(length, 256));
  const printable = countPrintable(ctx.bytes, offset, Math.min(length, 256));
  const mostlyText = printable > Math.min(length, 256) * 0.8;

  const summary = service
    ? `${length} bytes of ${service} payload (no dedicated dissector)`
    : `${length} bytes of application data`;

  ctx.add({
    id: 'app-data',
    name: service ? `${service} payload` : 'Application data',
    abbr: service ?? 'DATA',
    layer: 7,
    summary,
    offset,
    length,
    fields: [
      field({
        name: 'Payload',
        value: mostlyText ? (text ?? asciiOf(ctx.bytes, offset, Math.min(length, 120))).slice(0, 200) : hexPreview(ctx.bytes, offset, length, 24),
        offset,
        length,
        layer: 7,
        key: mostlyText ? 'payload.raw' : 'payload.encrypted',
        why: mostlyText
          ? 'These bytes are mostly printable text, so the protocol is probably a line-based one. Read the ASCII column in the hex pane — that is exactly how the first dissectors for these protocols were written.'
          : `These bytes are not printable text. They are either a binary protocol or encrypted. Either way you can still learn a great deal from the layers below: the endpoints, port ${app.servicePort}, the direction, the size, and the timing.`,
      }),
      field({
        name: 'Presentation format',
        value: mostlyText ? 'Text (ASCII/UTF-8)' : 'Binary or encrypted',
        offset,
        length: Math.min(length, 16),
        layer: 6,
        synthetic: true,
        key: 'presentation.model',
      }),
    ],
  });

  if (!ctx.info.includes('->')) ctx.info = summary;
}

function countPrintable(b: Uint8Array, offset: number, length: number): number {
  let n = 0;
  const end = Math.min(b.length, offset + length);
  for (let i = offset; i < end; i++) {
    const c = b[i];
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) n++;
  }
  return n;
}
