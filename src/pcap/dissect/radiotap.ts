/**
 * Radiotap header dissection — the one place a capture file carries genuinely
 * physical measurements.
 *
 * On wired Ethernet the adapter strips everything below the frame before the
 * capture driver sees it, so Layer 1 can only be described through metadata.
 * A Wi-Fi adapter in monitor mode does the opposite: the driver *prepends* a
 * radiotap header recording what the radio actually measured — received signal
 * strength in dBm, the channel frequency, which antenna heard it, the
 * modulation and coding scheme, whether the preamble was short, and whether
 * the hardware thought the FCS was valid.
 *
 * These are real bytes at real offsets, so unlike the synthesised frame
 * metadata they highlight in the hex pane like any other header.
 *
 * Radiotap is always little-endian, regardless of the host or the capture
 * file's own byte order.
 */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { hex } from '../bytes';
import { dissect80211 } from './ieee80211';

/** Field sizes and alignments, indexed by radiotap "present" bit. */
const FIELD_LAYOUT: Record<number, { size: number; align: number; name: string }> = {
  0: { size: 8, align: 8, name: 'TSFT' },
  1: { size: 1, align: 1, name: 'Flags' },
  2: { size: 1, align: 1, name: 'Rate' },
  3: { size: 4, align: 2, name: 'Channel' },
  4: { size: 2, align: 2, name: 'FHSS' },
  5: { size: 1, align: 1, name: 'Antenna signal' },
  6: { size: 1, align: 1, name: 'Antenna noise' },
  7: { size: 2, align: 2, name: 'Lock quality' },
  8: { size: 2, align: 2, name: 'TX attenuation' },
  9: { size: 2, align: 2, name: 'dB TX attenuation' },
  10: { size: 1, align: 1, name: 'dBm TX power' },
  11: { size: 1, align: 1, name: 'Antenna' },
  12: { size: 1, align: 1, name: 'dB antenna signal' },
  13: { size: 1, align: 1, name: 'dB antenna noise' },
  14: { size: 2, align: 2, name: 'RX flags' },
  15: { size: 2, align: 2, name: 'TX flags' },
  16: { size: 1, align: 1, name: 'RTS retries' },
  17: { size: 1, align: 1, name: 'Data retries' },
  18: { size: 8, align: 4, name: 'XChannel' },
  19: { size: 3, align: 1, name: 'MCS' },
  20: { size: 8, align: 4, name: 'A-MPDU status' },
  21: { size: 12, align: 2, name: 'VHT' },
};

const MCS_MODULATION = [
  'BPSK 1/2',
  'QPSK 1/2',
  'QPSK 3/4',
  '16-QAM 1/2',
  '16-QAM 3/4',
  '64-QAM 2/3',
  '64-QAM 3/4',
  '64-QAM 5/6',
];

/** 802.11n data rates in Mbit/s for one spatial stream. */
const HT_RATES: Record<string, number[]> = {
  '20-long': [6.5, 13, 19.5, 26, 39, 52, 58.5, 65],
  '20-short': [7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65, 72.2],
  '40-long': [13.5, 27, 40.5, 54, 81, 108, 121.5, 135],
  '40-short': [15, 30, 45, 60, 90, 120, 135, 150],
};

/** Turn a centre frequency into the channel number people actually say aloud. */
export function frequencyToChannel(freq: number): string {
  if (freq === 2484) return 'channel 14';
  if (freq >= 2412 && freq <= 2472) return `channel ${(freq - 2407) / 5}`;
  if (freq >= 5000 && freq < 5900) return `channel ${(freq - 5000) / 5}`;
  if (freq >= 5955 && freq <= 7115) return `channel ${(freq - 5950) / 5} (6 GHz)`;
  return 'channel unknown';
}

/** Plain-English reading of a received signal strength in dBm. */
export function signalQuality(dbm: number): string {
  if (dbm >= -50) return 'an excellent signal — the station is very close to the radio that captured this';
  if (dbm >= -60) return 'a strong signal, comfortably enough for the highest data rates';
  if (dbm >= -70) return 'a usable signal; expect the rate adaptation algorithm to back off from the top rates';
  if (dbm >= -80) return 'a weak signal — retries and low data rates are likely';
  return 'a very weak signal, at or below the practical noise floor for most adapters';
}

export function dissectRadiotap(ctx: DissectContext, offset: number): void {
  const b = ctx.bytes;
  if (!ctx.has(offset, 8)) {
    ctx.truncated('Radiotap', offset, 8);
    return;
  }

  const version = b[offset];
  const headerLength = b[offset + 2] | (b[offset + 3] << 8);
  if (headerLength < 8 || !ctx.has(offset, headerLength)) {
    ctx.warn(`Radiotap header claims ${headerLength} bytes, which does not fit in the captured frame.`);
    return;
  }

  // The present bitmask chains: bit 31 set means another 32-bit word follows.
  const presentWords: number[] = [];
  let wordOffset = offset + 4;
  let guard = 0;
  while (ctx.has(wordOffset, 4) && guard++ < 8) {
    const word = readU32LE(b, wordOffset);
    presentWords.push(word);
    wordOffset += 4;
    if ((word & 0x80000000) === 0) break;
  }

  const fields: Field[] = [
    field({
      name: 'Header revision',
      value: String(version),
      offset,
      length: 1,
      layer: 1,
      whatText: 'Radiotap version, always 0. The format is designed so a reader that meets an unknown field can still skip the whole header using its length.',
    }),
    field({
      name: 'Header length',
      value: `${headerLength} bytes`,
      offset: offset + 2,
      length: 2,
      layer: 1,
      whatText: 'Total size of the radiotap header. The 802.11 frame begins immediately after it.',
      why: 'These bytes were added by the capture driver, not transmitted over the air. Radiotap is a wrapper describing how the frame was received — it is metadata about the physical layer, delivered in-band.',
    }),
    field({
      name: 'Present flags',
      value: presentWords.map((w) => hex(w >>> 0, 8)).join(', '),
      offset: offset + 4,
      length: presentWords.length * 4,
      layer: 1,
      whatText: 'A bitmask saying which radio measurements this header carries, and in which order. Fields appear in bit order, each aligned to its own natural boundary.',
    }),
  ];

  // Walk the present bits and decode the fields that follow the bitmask.
  let cursor = wordOffset;
  const end = offset + headerLength;
  const summaryParts: string[] = [];
  let stopped = false;

  for (let wordIndex = 0; wordIndex < presentWords.length && !stopped; wordIndex++) {
    const word = presentWords[wordIndex];
    // Only the first word uses the standard namespace in the common case.
    if (wordIndex > 0) break;
    for (let bit = 0; bit <= 21; bit++) {
      if ((word & (1 << bit)) === 0) continue;
      const layout = FIELD_LAYOUT[bit];
      if (!layout) {
        stopped = true;
        ctx.warn(`Radiotap field bit ${bit} is not decoded by this tool; later fields were skipped.`);
        break;
      }
      // Each field starts at the next multiple of its alignment.
      const pad = (layout.align - ((cursor - offset) % layout.align)) % layout.align;
      cursor += pad;
      if (cursor + layout.size > end) {
        stopped = true;
        break;
      }
      fields.push(...decodeRadiotapField(ctx, bit, cursor, summaryParts));
      cursor += layout.size;
    }
  }

  ctx.term('radiotap', '802.11', 'wifi', 'wlan');

  ctx.add({
    id: 'radiotap',
    name: 'Radiotap (physical-layer radio metadata)',
    abbr: 'RADIOTAP',
    layer: 1,
    summary: summaryParts.join(' · ') || `${headerLength}-byte radio header`,
    offset,
    length: headerLength,
    fields,
    payload: { offset: offset + headerLength, length: Math.max(0, b.length - offset - headerLength) },
  });

  ctx.info = summaryParts.join(' ');
  dissect80211(ctx, offset + headerLength);
}

function readU32LE(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

function readU16LE(b: Uint8Array, o: number): number {
  return b[o] | (b[o + 1] << 8);
}

function decodeRadiotapField(ctx: DissectContext, bit: number, o: number, summary: string[]): Field[] {
  const b = ctx.bytes;
  switch (bit) {
    case 0: {
      const lo = readU32LE(b, o);
      const hi = readU32LE(b, o + 4);
      const usec = hi * 4294967296 + lo;
      return [
        field({
          name: 'MAC timestamp (TSF)',
          value: `${usec} µs`,
          offset: o,
          length: 8,
          layer: 1,
          whatText: 'The value of the radio\'s Timing Synchronisation Function counter when the first bit of the frame arrived, in microseconds since the cell started.',
          why: 'This is a hardware timestamp taken at the radio itself, not a software timestamp taken when the driver got around to the frame. Every station in a Wi-Fi cell keeps its TSF synchronised to the access point\'s beacons, which is what makes power saving and coordinated airtime possible.',
        }),
      ];
    }
    case 1: {
      const flags = b[o];
      const names: string[] = [];
      if (flags & 0x02) names.push('short preamble');
      if (flags & 0x04) names.push('WEP');
      if (flags & 0x08) names.push('fragmented');
      if (flags & 0x10) names.push('FCS present');
      if (flags & 0x20) names.push('padding');
      if (flags & 0x40) names.push('BAD FCS');
      if (flags & 0x80) names.push('short guard interval');
      return [
        field({
          name: 'Radio flags',
          value: `${hex(flags, 2)}${names.length ? ` (${names.join(', ')})` : ''}`,
          offset: o,
          length: 1,
          layer: 1,
          whatText: 'Properties of the transmission the radio observed: preamble length, whether the frame check sequence is still attached, and whether the hardware thought it was valid.',
          why:
            flags & 0x40
              ? 'The hardware flagged a bad FCS. On Wi-Fi this is normal and informative rather than alarming: a monitor-mode capture hears frames from stations too far away to decode cleanly, and a wall of bad-FCS frames is exactly what interference or a weak client looks like.'
              : flags & 0x10
                ? 'The FCS is still attached to the end of this frame — unusual, and worth knowing, because on wired Ethernet the adapter almost always strips it before you ever see it.'
                : 'The adapter validated and removed the frame check sequence, so what follows is the 802.11 frame proper.',
          note: flags & 0x40 ? 'warn' : undefined,
        }),
      ];
    }
    case 2: {
      const rate = b[o] / 2;
      summary.push(`${rate} Mb/s`);
      return [
        field({
          name: 'Data rate',
          value: `${rate} Mbit/s`,
          offset: o,
          length: 1,
          layer: 1,
          whatText: 'The over-the-air bit rate this frame was sent at, in units of 500 kbit/s.',
          why:
            rate <= 11
              ? `${rate} Mbit/s is a legacy 802.11b rate. Management frames such as beacons are deliberately sent this slowly so that every station in range, however far away, can decode them — which is also why a busy cell spends a surprising share of its airtime on beacons.`
              : `At ${rate} Mbit/s a 1500-byte frame occupies the medium for roughly ${((1500 * 8) / rate).toFixed(0)} microseconds. Wi-Fi is half duplex and shared, so airtime, not bandwidth, is the resource that actually runs out.`,
        }),
      ];
    }
    case 3: {
      const freq = readU16LE(b, o);
      const chFlags = readU16LE(b, o + 2);
      const band: string[] = [];
      if (chFlags & 0x0080) band.push('2.4 GHz');
      if (chFlags & 0x0100) band.push('5 GHz');
      if (chFlags & 0x0020) band.push('CCK');
      if (chFlags & 0x0040) band.push('OFDM');
      summary.push(`${(freq / 1000).toFixed(3)} GHz`);
      return [
        field({
          name: 'Channel frequency',
          value: `${freq} MHz (${frequencyToChannel(freq)})`,
          offset: o,
          length: 2,
          layer: 1,
          whatText: 'The centre frequency the radio was tuned to when it heard this frame.',
          why: 'This is about as physical as a capture gets: an actual carrier frequency in megahertz. A monitor-mode capture only ever sees one channel at a time, which is why a Wi-Fi capture that seems to be missing traffic is usually tuned to the wrong channel rather than broken.',
        }),
        field({
          name: 'Channel flags',
          value: `${hex(chFlags, 4)}${band.length ? ` (${band.join(', ')})` : ''}`,
          offset: o + 2,
          length: 2,
          layer: 1,
          whatText: 'Which band this channel is in and which modulation family is in use — CCK for the legacy 802.11b rates, OFDM for everything since.',
        }),
      ];
    }
    case 5: {
      const dbm = (b[o] << 24) >> 24; // sign-extend
      summary.push(`${dbm} dBm`);
      return [
        field({
          name: 'Antenna signal (RSSI)',
          value: `${dbm} dBm`,
          offset: o,
          length: 1,
          layer: 1,
          whatText: 'Received signal strength at the antenna, in decibels relative to one milliwatt. It is negative because a received Wi-Fi signal is a tiny fraction of a milliwatt.',
          why: `${dbm} dBm is ${signalQuality(dbm)}. The scale is logarithmic: every 3 dB is a halving of power, so -60 dBm carries a thousandth of the power of -30 dBm. This single byte is the most physical number in the entire capture — everything else in the file is already digital.`,
          note: dbm < -80 ? 'warn' : undefined,
        }),
      ];
    }
    case 6: {
      const dbm = (b[o] << 24) >> 24;
      return [
        field({
          name: 'Antenna noise',
          value: `${dbm} dBm`,
          offset: o,
          length: 1,
          layer: 1,
          whatText: 'The noise floor the radio measured on this channel.',
          why: 'Signal minus noise is the signal-to-noise ratio, and it is SNR rather than raw signal strength that decides which modulation rates can be decoded. A strong signal in a noisy room still gets slow.',
        }),
      ];
    }
    case 11:
      return [
        field({
          name: 'Antenna',
          value: String(b[o]),
          offset: o,
          length: 1,
          layer: 1,
          whatText: 'Which physical antenna received this frame, numbered from zero.',
          why: 'Multi-antenna radios report per-antenna signal strength. Comparing antennas is how you tell a genuinely weak client from one that is simply badly positioned relative to one of the aerials.',
        }),
      ];
    case 14: {
      const rxFlags = readU16LE(b, o);
      return [
        field({
          name: 'RX flags',
          value: hex(rxFlags, 4),
          offset: o,
          length: 2,
          layer: 1,
          whatText: 'Receive-side properties. Bit 1 means the PLCP header failed its own CRC check.',
        }),
      ];
    }
    case 19: {
      const known = b[o];
      const flags = b[o + 1];
      const mcs = b[o + 2];
      const bandwidth = known & 0x01 ? [20, 40, 20, 20][flags & 0x03] : 20;
      const shortGi = (flags & 0x04) !== 0;
      const streams = Math.floor(mcs / 8) + 1;
      const rateKey = `${bandwidth}-${shortGi ? 'short' : 'long'}`;
      const base = HT_RATES[rateKey]?.[mcs % 8];
      const rate = base ? (base * streams).toFixed(1) : undefined;
      if (rate) summary.push(`MCS ${mcs} · ${rate} Mb/s`);
      return [
        field({
          name: 'MCS index',
          value: `${mcs}${rate ? ` (${rate} Mbit/s)` : ''}`,
          offset: o + 2,
          length: 1,
          layer: 1,
          whatText: 'The 802.11n Modulation and Coding Scheme: one number that fixes the modulation, the forward error correction rate and the number of spatial streams.',
          why: `MCS ${mcs} means ${MCS_MODULATION[mcs % 8]} on ${streams} spatial stream${streams === 1 ? '' : 's'}, which at ${bandwidth} MHz with a ${shortGi ? 'short' : 'long'} guard interval is ${rate ?? 'an implementation-defined'} Mbit/s. Higher MCS packs more bits into each symbol, and needs a correspondingly better signal to decode — which is why rate adaptation walks this number up and down as a client moves around.`,
        }),
        field({
          name: 'MCS bandwidth',
          value: `${bandwidth} MHz`,
          offset: o + 1,
          length: 1,
          bits: { offset: 6, length: 2 },
          layer: 1,
          whatText: 'Channel width. Wider channels carry more bits but overlap more neighbours, so in a crowded 2.4 GHz band 40 MHz often performs worse than 20.',
        }),
        field({
          name: 'Guard interval',
          value: shortGi ? '400 ns (short)' : '800 ns (long)',
          offset: o + 1,
          length: 1,
          bits: { offset: 5, length: 1 },
          layer: 1,
          whatText: 'The quiet gap between symbols that lets multipath reflections die away before the next one starts.',
          why: 'Shortening it from 800 to 400 nanoseconds buys about 11% more throughput, at the cost of being less tolerant of echo — a direct, physical trade between speed and robustness.',
        }),
      ];
    }
    default: {
      const layout = FIELD_LAYOUT[bit];
      return [
        field({
          name: layout.name,
          value: `${layout.size} bytes`,
          offset: o,
          length: layout.size,
          layer: 1,
          whatText: 'A radiotap field this tool records but does not interpret in detail.',
        }),
      ];
    }
  }
}
