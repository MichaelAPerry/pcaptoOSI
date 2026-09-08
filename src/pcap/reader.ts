/**
 * Capture-file readers.
 *
 * Two container formats are supported, both parsed here from first principles
 * so the app has no runtime parsing dependency and works completely offline:
 *
 *   - classic libpcap ("pcap"), in all four magic-number variants
 *     (big/little endian x microsecond/nanosecond timestamps);
 *   - PCAP Next Generation ("pcapng"), including Section Header, Interface
 *     Description, Enhanced Packet, Simple Packet and the obsolete Packet
 *     block, with per-interface timestamp resolution.
 *
 * Everything is read out of an ArrayBuffer that came from a <input type=file>
 * or a drop event. No bytes ever leave the browser.
 */

import type { CaptureMeta, InterfaceDesc, PacketOptions, RawPacket } from './types';
import { linkTypeName } from './linktypes';

export class CaptureParseError extends Error {}

export interface ReadResult {
  meta: CaptureMeta;
  packets: RawPacket[];
  warnings: string[];
}

const PCAP_MAGIC_BE_US = 0xa1b2c3d4;
const PCAP_MAGIC_LE_US = 0xd4c3b2a1;
const PCAP_MAGIC_BE_NS = 0xa1b23c4d;
const PCAP_MAGIC_LE_NS = 0x4d3cb2a1;
const PCAPNG_SHB = 0x0a0d0d0a;

/** Hard cap so a pathological file cannot lock the browser tab up forever. */
const MAX_PACKETS = 200_000;

export function readCapture(buffer: ArrayBuffer): ReadResult {
  if (buffer.byteLength < 4) {
    throw new CaptureParseError('File is too small to be a capture (fewer than 4 bytes).');
  }
  const view = new DataView(buffer);
  const first = view.getUint32(0, false);
  if (first === PCAPNG_SHB) return readPcapng(buffer);
  if (
    first === PCAP_MAGIC_BE_US ||
    first === PCAP_MAGIC_LE_US ||
    first === PCAP_MAGIC_BE_NS ||
    first === PCAP_MAGIC_LE_NS
  ) {
    return readPcap(buffer);
  }
  throw new CaptureParseError(
    `Unrecognised file magic 0x${first.toString(16).padStart(8, '0')}. ` +
      'Expected a libpcap (.pcap) or pcapng (.pcapng) capture. ' +
      'Gzip-compressed captures (.pcap.gz) must be decompressed first.',
  );
}

/* ------------------------------------------------------------------ pcap — */

function readPcap(buffer: ArrayBuffer): ReadResult {
  const view = new DataView(buffer);
  const magic = view.getUint32(0, false);
  const little = magic === PCAP_MAGIC_LE_US || magic === PCAP_MAGIC_LE_NS;
  const nanos = magic === PCAP_MAGIC_BE_NS || magic === PCAP_MAGIC_LE_NS;

  if (buffer.byteLength < 24) {
    throw new CaptureParseError('Truncated pcap file: the 24-byte global header is incomplete.');
  }

  const versionMajor = view.getUint16(4, little);
  const versionMinor = view.getUint16(6, little);
  const snapLen = view.getUint32(16, little);
  const linkType = view.getUint32(20, little) & 0x0fffffff;

  const warnings: string[] = [];
  if (versionMajor !== 2 || versionMinor !== 4) {
    warnings.push(`Unusual pcap version ${versionMajor}.${versionMinor} (2.4 is the norm).`);
  }

  const iface: InterfaceDesc = {
    id: 0,
    name: 'capture device 0',
    description: 'Classic pcap files describe a single capture interface in the global header.',
    linkType,
    linkTypeName: linkTypeName(linkType),
    snapLen,
    timeResolution: nanos ? 1e9 : 1e6,
  };

  const meta: CaptureMeta = {
    format: 'pcap',
    linkType,
    linkTypeName: linkTypeName(linkType),
    endianness: little ? 'little-endian' : 'big-endian',
    snapLen,
    interfaces: [iface],
  };

  const packets: RawPacket[] = [];
  const bytes = new Uint8Array(buffer);
  let offset = 24;
  let index = 0;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, little);
    const tsFrac = view.getUint32(offset + 4, little);
    const inclLen = view.getUint32(offset + 8, little);
    const origLen = view.getUint32(offset + 12, little);
    offset += 16;

    if (inclLen > buffer.byteLength - offset) {
      warnings.push(
        `Packet ${index + 1} claims ${inclLen} captured bytes but only ` +
          `${buffer.byteLength - offset} remain in the file; the capture is truncated.`,
      );
      break;
    }
    if (inclLen > 262144) {
      warnings.push(`Packet ${index + 1} has an implausible captured length (${inclLen}); stopping.`);
      break;
    }

    index++;
    packets.push({
      index,
      timestamp: tsSec + tsFrac / (nanos ? 1e9 : 1e6),
      capturedLength: inclLen,
      originalLength: origLen,
      interfaceId: 0,
      bytes: bytes.subarray(offset, offset + inclLen),
    });
    offset += inclLen;
    if (packets.length >= MAX_PACKETS) {
      warnings.push(`Stopped after ${MAX_PACKETS} packets to keep the browser responsive.`);
      break;
    }
  }

  return { meta, packets, warnings };
}

/* ---------------------------------------------------------------- pcapng — */

interface NgOption {
  code: number;
  value: Uint8Array;
}

function parseOptions(bytes: Uint8Array, start: number, end: number, little: boolean): NgOption[] {
  const out: NgOption[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let o = start;
  while (o + 4 <= end) {
    const code = view.getUint16(o, little);
    const len = view.getUint16(o + 2, little);
    o += 4;
    if (code === 0) break; // opt_endofopt
    if (o + len > end) break;
    out.push({ code, value: bytes.subarray(o, o + len) });
    o += len + ((4 - (len % 4)) % 4);
  }
  return out;
}

function decodeText(value: Uint8Array): string | undefined {
  try {
    const text = new TextDecoder('utf-8').decode(value).replace(/\0+$/, '');
    return text.length > 0 ? text : undefined;
  } catch {
    return undefined;
  }
}

function optionText(opt: NgOption | undefined): string | undefined {
  return opt ? decodeText(opt.value) : undefined;
}

/**
 * Decode an Enhanced Packet Block's options.
 *
 * epb_flags (code 2) is the interesting one: its low bits say which direction
 * the frame was travelling through the adapter and how it was received, and
 * its top bits carry link-layer error flags such as a hardware-detected CRC
 * failure. That is real physical-layer information, and it is the only place a
 * capture file records it.
 */
function parsePacketOptions(
  bytes: Uint8Array,
  start: number,
  end: number,
  little: boolean,
): PacketOptions | undefined {
  if (start >= end) return undefined;
  const opts = parseOptions(bytes, start, end, little);
  if (opts.length === 0) return undefined;

  const result: PacketOptions = {};
  const flagsOpt = opts.find((o) => o.code === 2);
  if (flagsOpt && flagsOpt.value.length >= 4) {
    const dv = new DataView(flagsOpt.value.buffer, flagsOpt.value.byteOffset, 4);
    const flags = dv.getUint32(0, little);
    result.direction = (flags & 0x03) as 0 | 1 | 2;
    result.receptionType = (flags >> 2) & 0x07;
    const fcsLen = (flags >> 5) & 0x0f;
    if (fcsLen > 0) result.fcsLength = fcsLen;
    result.errorFlags = flags >>> 16;
  }
  result.comment = optionText(opts.find((o) => o.code === 1));

  return Object.values(result).some((v) => v !== undefined) ? result : undefined;
}

function readPcapng(buffer: ArrayBuffer): ReadResult {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const warnings: string[] = [];
  const packets: RawPacket[] = [];
  const interfaces: InterfaceDesc[] = [];

  let little = true;
  let offset = 0;
  let sectionComment: string | undefined;
  let index = 0;

  while (offset + 12 <= buffer.byteLength) {
    // The section header block re-establishes byte order for everything after it.
    const rawType = view.getUint32(offset, false);
    if (rawType === PCAPNG_SHB) {
      const bom = view.getUint32(offset + 8, false);
      if (bom === 0x1a2b3c4d) little = false;
      else if (bom === 0x4d3c2b1a) little = true;
      else throw new CaptureParseError('pcapng section header has an invalid byte-order magic.');
    }

    const blockType = view.getUint32(offset, little);
    const blockLen = view.getUint32(offset + 4, little);

    if (blockLen < 12 || offset + blockLen > buffer.byteLength) {
      warnings.push(
        `pcapng block at offset ${offset} declares length ${blockLen}, which does not fit in the file; stopping.`,
      );
      break;
    }

    const bodyStart = offset + 8;
    const bodyEnd = offset + blockLen - 4;

    switch (blockType) {
      case PCAPNG_SHB: {
        const opts = parseOptions(bytes, bodyStart + 16, bodyEnd, little);
        sectionComment =
          optionText(opts.find((o) => o.code === 1)) ??
          optionText(opts.find((o) => o.code === 4)) ??
          sectionComment;
        break;
      }
      case 0x00000001: {
        // Interface Description Block
        const linkType = view.getUint16(bodyStart, little);
        const snapLen = view.getUint32(bodyStart + 4, little);
        const opts = parseOptions(bytes, bodyStart + 8, bodyEnd, little);
        const tsresolOpt = opts.find((o) => o.code === 9);
        let timeResolution = 1e6;
        if (tsresolOpt && tsresolOpt.value.length >= 1) {
          const raw = tsresolOpt.value[0];
          timeResolution = raw & 0x80 ? Math.pow(2, raw & 0x7f) : Math.pow(10, raw);
        }
        // if_speed is a 64-bit value; JavaScript numbers hold it exactly up to
        // 2^53, which is far above any real interface bit rate.
        const speedOpt = opts.find((o) => o.code === 8);
        let speed: number | undefined;
        if (speedOpt && speedOpt.value.length >= 8) {
          const dv = new DataView(speedOpt.value.buffer, speedOpt.value.byteOffset, 8);
          const lo = dv.getUint32(little ? 0 : 4, little);
          const hi = dv.getUint32(little ? 4 : 0, little);
          speed = hi * 4294967296 + lo;
        }
        const fcsOpt = opts.find((o) => o.code === 13);
        const filterOpt = opts.find((o) => o.code === 11);

        interfaces.push({
          id: interfaces.length,
          name: optionText(opts.find((o) => o.code === 2)) ?? `interface ${interfaces.length}`,
          description: optionText(opts.find((o) => o.code === 3)),
          os: optionText(opts.find((o) => o.code === 12)),
          hardware: optionText(opts.find((o) => o.code === 15)),
          // if_filter's first byte is a code identifying the filter syntax.
          filter: filterOpt && filterOpt.value.length > 1 ? decodeText(filterOpt.value.subarray(1)) : undefined,
          speed,
          fcsLength: fcsOpt && fcsOpt.value.length >= 1 ? fcsOpt.value[0] & 0x1f : undefined,
          linkType,
          linkTypeName: linkTypeName(linkType),
          snapLen,
          timeResolution,
        });
        break;
      }
      case 0x00000006: {
        // Enhanced Packet Block
        const interfaceId = view.getUint32(bodyStart, little);
        const tsHigh = view.getUint32(bodyStart + 4, little);
        const tsLow = view.getUint32(bodyStart + 8, little);
        const capLen = view.getUint32(bodyStart + 12, little);
        const origLen = view.getUint32(bodyStart + 16, little);
        const dataStart = bodyStart + 20;
        if (dataStart + capLen > bodyEnd) {
          warnings.push(`Enhanced packet block ${index + 1} is truncated; skipping it.`);
          break;
        }
        const res = interfaces[interfaceId]?.timeResolution ?? 1e6;
        const ticks = tsHigh * 4294967296 + tsLow;
        // Options sit after the (4-byte aligned) packet data.
        const paddedEnd = dataStart + capLen + ((4 - (capLen % 4)) % 4);
        const packetOptions = parsePacketOptions(bytes, paddedEnd, bodyEnd, little);
        index++;
        packets.push({
          index,
          timestamp: ticks / res,
          capturedLength: capLen,
          originalLength: origLen,
          interfaceId,
          options: packetOptions,
          bytes: bytes.subarray(dataStart, dataStart + capLen),
        });
        break;
      }
      case 0x00000003: {
        // Simple Packet Block — no timestamp, no per-packet interface.
        const origLen = view.getUint32(bodyStart, little);
        const capLen = Math.min(origLen, bodyEnd - (bodyStart + 4));
        index++;
        packets.push({
          index,
          timestamp: 0,
          capturedLength: capLen,
          originalLength: origLen,
          interfaceId: 0,
          bytes: bytes.subarray(bodyStart + 4, bodyStart + 4 + capLen),
        });
        break;
      }
      case 0x00000002: {
        // Obsolete Packet Block, still found in older files.
        const interfaceId = view.getUint16(bodyStart, little);
        const tsHigh = view.getUint32(bodyStart + 4, little);
        const tsLow = view.getUint32(bodyStart + 8, little);
        const capLen = view.getUint32(bodyStart + 12, little);
        const origLen = view.getUint32(bodyStart + 16, little);
        const dataStart = bodyStart + 20;
        if (dataStart + capLen > bodyEnd) break;
        const res = interfaces[interfaceId]?.timeResolution ?? 1e6;
        index++;
        packets.push({
          index,
          timestamp: (tsHigh * 4294967296 + tsLow) / res,
          capturedLength: capLen,
          originalLength: origLen,
          interfaceId,
          bytes: bytes.subarray(dataStart, dataStart + capLen),
        });
        break;
      }
      default:
        // Name Resolution, Interface Statistics, Decryption Secrets, custom
        // blocks and anything else are skipped: they carry no frame bytes.
        break;
    }

    offset += blockLen;
    if (packets.length >= MAX_PACKETS) {
      warnings.push(`Stopped after ${MAX_PACKETS} packets to keep the browser responsive.`);
      break;
    }
  }

  if (interfaces.length === 0) {
    throw new CaptureParseError('pcapng file contains no Interface Description Block.');
  }

  const meta: CaptureMeta = {
    format: 'pcapng',
    linkType: interfaces[0].linkType,
    linkTypeName: interfaces[0].linkTypeName,
    endianness: little ? 'little-endian' : 'big-endian',
    snapLen: interfaces[0].snapLen,
    interfaces,
    comment: sectionComment,
  };

  return { meta, packets, warnings };
}
