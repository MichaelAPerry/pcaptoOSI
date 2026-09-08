/** Glue: read a capture file and dissect every packet in it. */

import { readCapture, CaptureParseError } from './reader';
import { dissectPacket } from './dissect';
import { resetFieldIds } from './dissect/context';
import type { Capture, DissectedPacket } from './types';

export { CaptureParseError };

export function loadCapture(fileName: string, buffer: ArrayBuffer): Capture {
  const { meta, packets, warnings } = readCapture(buffer);
  resetFieldIds();

  const first = packets[0]?.timestamp ?? 0;
  const dissected: DissectedPacket[] = [];
  let previous: number | undefined;

  for (const raw of packets) {
    dissected.push(dissectPacket(raw, meta, first, previous));
    previous = raw.timestamp;
  }

  return {
    fileName,
    fileSize: buffer.byteLength,
    meta,
    packets: dissected,
    warnings,
  };
}

/**
 * The quick filter.
 *
 * Deliberately not a Wireshark display-filter clone: students should be able
 * to type "tcp", "443", "dns" or an IP address and immediately see fewer rows.
 * Space-separated terms are ANDed, a leading "-" negates a term, and
 * "field:value" forms restrict the match to one column.
 */
export function filterPackets(packets: DissectedPacket[], query: string): DissectedPacket[] {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return packets;
  const terms = trimmed.split(/\s+/);

  return packets.filter((p) => {
    const haystack = [
      p.protocol,
      p.source,
      p.destination,
      p.info,
      p.searchIndex,
      String(p.index),
      String(p.originalLength),
    ]
      .join(' ')
      .toLowerCase();

    return terms.every((term) => {
      let negate = false;
      let t = term;
      if (t.startsWith('-') && t.length > 1) {
        negate = true;
        t = t.slice(1);
      }
      let matched: boolean;
      const colon = t.indexOf(':');
      if (colon > 0) {
        const key = t.slice(0, colon);
        const value = t.slice(colon + 1);
        switch (key) {
          case 'ip':
          case 'addr':
            matched = p.source.toLowerCase().includes(value) || p.destination.toLowerCase().includes(value);
            break;
          case 'src':
            matched = p.source.toLowerCase().includes(value);
            break;
          case 'dst':
            matched = p.destination.toLowerCase().includes(value);
            break;
          case 'proto':
            matched = p.protocol.toLowerCase().includes(value);
            break;
          case 'port':
            matched = new RegExp(`(^| )${escapeRegExp(value)}( |$)`).test(p.searchIndex);
            break;
          case 'info':
            matched = p.info.toLowerCase().includes(value);
            break;
          default:
            matched = haystack.includes(t);
            break;
        }
      } else {
        matched = haystack.includes(t);
      }
      return negate ? !matched : matched;
    });
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Distinct protocol names present in a capture, for the filter chips. */
export function protocolCounts(packets: DissectedPacket[]): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const p of packets) counts.set(p.protocol, (counts.get(p.protocol) ?? 0) + 1);
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}
