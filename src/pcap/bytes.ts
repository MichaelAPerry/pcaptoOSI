/** Small byte/formatting helpers shared by the reader and every dissector. */

export function hex(n: number, width = 2): string {
  return '0x' + n.toString(16).toUpperCase().padStart(width, '0');
}

export function toHexByte(n: number): string {
  return n.toString(16).toUpperCase().padStart(2, '0');
}

export function formatMac(bytes: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) parts.push(toHexByte(bytes[offset + i] ?? 0));
  return parts.join(':').toLowerCase();
}

export function formatIPv4(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/** RFC 5952 style IPv6 formatting, including the longest-run "::" collapse. */
export function formatIPv6(bytes: Uint8Array, offset: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push((bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1]);
  }
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      const len = i - runStart;
      if (len > bestLen) {
        bestLen = len;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    if (bestLen > 1 && i === bestStart) {
      parts.push('');
      i += bestLen - 1;
      if (i === 7) parts.push('');
      continue;
    }
    parts.push(groups[i].toString(16));
  }
  let out = parts.join(':');
  if (bestLen > 1 && bestStart === 0) out = ':' + out;
  return out;
}

export function readU16BE(b: Uint8Array, o: number): number {
  return ((b[o] << 8) | b[o + 1]) >>> 0;
}

export function readU24BE(b: Uint8Array, o: number): number {
  return ((b[o] << 16) | (b[o + 1] << 8) | b[o + 2]) >>> 0;
}

export function readU32BE(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

/** Decode a byte range as ASCII, replacing non-printable bytes with a dot. */
export function asciiOf(b: Uint8Array, offset: number, length: number): string {
  let out = '';
  const end = Math.min(b.length, offset + length);
  for (let i = offset; i < end; i++) {
    const c = b[i];
    out += c >= 0x20 && c <= 0x7e ? String.fromCharCode(c) : '.';
  }
  return out;
}

/** Strict UTF-8 decode of a byte range; returns null when it is not UTF-8. */
export function utf8Of(b: Uint8Array, offset: number, length: number): string | null {
  try {
    const dec = new TextDecoder('utf-8', { fatal: true });
    return dec.decode(b.subarray(offset, Math.min(b.length, offset + length)));
  } catch {
    return null;
  }
}

/** Latin-1 decode — never throws, used for HTTP header parsing. */
export function latin1Of(b: Uint8Array, offset: number, length: number): string {
  let out = '';
  const end = Math.min(b.length, offset + length);
  for (let i = offset; i < end; i++) out += String.fromCharCode(b[i]);
  return out;
}

/** Space-separated hex dump of a byte range, truncated for display. */
export function hexPreview(b: Uint8Array, offset: number, length: number, max = 24): string {
  const end = Math.min(b.length, offset + length);
  const parts: string[] = [];
  for (let i = offset; i < end && parts.length < max; i++) parts.push(toHexByte(b[i]));
  const more = end - offset > max ? '...' : '';
  return parts.join(' ') + more;
}

/**
 * The standard Internet checksum (RFC 1071): one's-complement sum of 16-bit
 * words, then complemented. Used to verify IPv4/ICMP/TCP/UDP checksums so the
 * inspector can tell a student when a capture contains a genuinely corrupt
 * packet (or, far more often, NIC checksum offload).
 */
export function internetChecksum(words: Uint8Array[], skip?: { start: number; length: number }): number {
  let sum = 0;
  let index = 0;
  let carryByte = -1;
  for (const chunk of words) {
    for (let i = 0; i < chunk.length; i++) {
      let byte = chunk[i];
      if (skip && index >= skip.start && index < skip.start + skip.length) byte = 0;
      if (carryByte < 0) {
        carryByte = byte;
      } else {
        sum += (carryByte << 8) | byte;
        carryByte = -1;
      }
      index++;
    }
  }
  if (carryByte >= 0) sum += carryByte << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

/** Format a bit range as a Wireshark-style mask string, e.g. "..0. .... ". */
export function bitMaskString(value: number, totalBits: number, offset: number, length: number): string {
  let out = '';
  for (let i = 0; i < totalBits; i++) {
    const inRange = i >= offset && i < offset + length;
    if (inRange) {
      const shift = totalBits - 1 - i;
      out += (value >>> shift) & 1 ? '1' : '0';
    } else {
      out += '.';
    }
    if ((i + 1) % 4 === 0 && i + 1 < totalBits) out += ' ';
  }
  return out;
}
