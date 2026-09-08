/**
 * Core data model shared by the capture-file readers, the protocol dissectors
 * and the UI.
 *
 * The whole application is built around one idea: every value we show the
 * student is anchored to a byte range inside the captured frame. That is what
 * makes the "hover a field, light up the hex" behaviour possible, and it is
 * what keeps the OSI mapping honest — a layer is not an abstract label here,
 * it is a concrete span of bytes on the wire.
 */

/** The seven OSI layers, used as a numeric key everywhere in the app. */
export type OsiLayer = 1 | 2 | 3 | 4 | 5 | 6 | 7;

/** A bit range inside a field, used for things like TCP flags or DSCP/ECN. */
export interface BitRange {
  /** Bit offset counted from the MSB of the first byte of the field. */
  offset: number;
  /** Number of bits. */
  length: number;
}

/**
 * A single dissected header field.
 *
 * `offset`/`length` are always absolute byte coordinates inside the frame
 * buffer, so the hex viewer can highlight them without knowing anything about
 * the protocol that produced them.
 */
export interface Field {
  /** Stable id, unique within a packet. Used as React key and hover target. */
  id: string;
  /** Short human label, e.g. "Time to Live". */
  name: string;
  /** Formatted value for display, e.g. "64". */
  value: string;
  /** Absolute byte offset of the field inside the frame. */
  offset: number;
  /** Field length in bytes (0 for purely synthetic/derived entries). */
  length: number;
  /** Optional bit range for sub-byte fields. */
  bits?: BitRange;
  /** OSI layer this field belongs to. */
  layer: OsiLayer;
  /** "What does this field do?" — static, from the glossary. */
  what: string;
  /** "Why does *this* value matter?" — computed from the actual bytes. */
  why?: string;
  /** Nested fields (flag bits, TLV options, DNS records, HTTP headers...). */
  children?: Field[];
  /** Set when the field is derived rather than read straight off the wire. */
  synthetic?: boolean;
  /** Severity hint used to colour anomalous values (bad checksum, RST, ...). */
  note?: 'info' | 'warn' | 'error';
}

/**
 * One protocol header inside a frame (Ethernet, IPv4, TCP, TLS, HTTP, ...).
 * A frame is dissected into an ordered list of these, outermost first.
 */
export interface ProtocolLayer {
  /** Short id, e.g. "ipv4". */
  id: string;
  /** Display name, e.g. "Internet Protocol Version 4". */
  name: string;
  /** Abbreviation shown in the packet list, e.g. "IPv4". */
  abbr: string;
  /** Primary OSI layer this header lives at. */
  layer: OsiLayer;
  /**
   * Extra layers this header also contributes to. TLS, for example, is
   * primarily a Layer 6 citizen but also carries Layer 5 session material.
   */
  alsoLayers?: OsiLayer[];
  /** One-line summary, e.g. "192.168.1.10 -> 93.184.216.34". */
  summary: string;
  /** Absolute byte offset of this header inside the frame. */
  offset: number;
  /** Byte length of this header (header only, not the payload it carries). */
  length: number;
  /** The fields of this header. */
  fields: Field[];
  /**
   * Byte range of the payload this header encapsulates, when known. Used by
   * the encapsulation diagram to draw the Russian-doll nesting.
   */
  payload?: { offset: number; length: number };
  /**
   * Virtual layers are not headers on the wire — they are the synthesised
   * Layer 1 frame metadata and the Layer 5/6 commentary that the TCP/IP stack
   * does not give its own header. They appear in the OSI inspector but are
   * skipped by the encapsulation diagram, which only nests real bytes.
   */
  virtual?: boolean;
  /**
   * Trailer bytes that are part of the frame but not part of the protocol
   * stack — Ethernet padding, most commonly. They are real bytes, so they are
   * highlighted and shown, but they must not become the packet's "Protocol".
   */
  trailer?: boolean;
  /**
   * An absence marker: a virtual entry whose whole purpose is to explain why a
   * layer is empty, as with ARP at Layer 3 or an 802.11 acknowledgement above
   * Layer 2. It carries the explanation without making the layer count as
   * present, so the inspector still dims it.
   */
  absence?: boolean;
}

/** Physical-interface metadata recovered from the capture file itself. */
export interface CaptureMeta {
  /** Human name of the container format. */
  format: 'pcap' | 'pcapng';
  /** libpcap link-layer type number (1 = Ethernet). */
  linkType: number;
  /** Human name for the link type. */
  linkTypeName: string;
  /** Byte order of the file as written. */
  endianness: 'little-endian' | 'big-endian';
  /** Snapshot length configured by the capturing tool. */
  snapLen: number;
  /** Per-interface descriptions (pcapng IDBs, or a synthetic one for pcap). */
  interfaces: InterfaceDesc[];
  /** Optional free-text comment from a pcapng Section Header Block. */
  comment?: string;
}

export interface InterfaceDesc {
  id: number;
  name?: string;
  description?: string;
  linkType: number;
  linkTypeName: string;
  snapLen: number;
  /** Divisor for timestamps: 1e6 for microseconds, 1e9 for nanoseconds. */
  timeResolution: number;
  os?: string;
  /** if_speed: interface bit rate in bits per second, when the capture says. */
  speed?: number;
  /** if_fcslen: how many bits of frame check sequence the frames still carry. */
  fcsLength?: number;
  /** if_hardware: free-text description of the physical adapter. */
  hardware?: string;
  /** if_filter: the capture filter that was in effect. */
  filter?: string;
}

/**
 * Per-packet metadata from a pcapng Enhanced Packet Block's options.
 *
 * This is genuinely physical-layer information — which way the frame was
 * travelling through the adapter, whether the hardware flagged a CRC error,
 * whether the FCS is still attached — and it is the sort of thing that is easy
 * to miss because it lives in optional trailing fields rather than in the
 * block header.
 */
export interface PacketOptions {
  /** 0 = unknown, 1 = inbound, 2 = outbound. */
  direction?: 0 | 1 | 2;
  /** 0 unspecified, 1 unicast, 2 multicast, 3 broadcast, 4 promiscuous. */
  receptionType?: number;
  /** FCS length in bits, when the per-packet option overrides the interface. */
  fcsLength?: number;
  /** Link-layer error bits reported by the capture hardware. */
  errorFlags?: number;
  /** A human comment the capturing tool or an analyst attached to this frame. */
  comment?: string;
}

/** A raw record read out of the capture file, before dissection. */
export interface RawPacket {
  /** 1-based packet number, as shown in the packet list. */
  index: number;
  /** Seconds since the Unix epoch, including the fractional part. */
  timestamp: number;
  /** Number of bytes actually stored in the file. */
  capturedLength: number;
  /** Number of bytes that were on the wire (>= capturedLength if truncated). */
  originalLength: number;
  /** Index into CaptureMeta.interfaces. */
  interfaceId: number;
  /** pcapng per-packet options, when the block carried any. */
  options?: PacketOptions;
  /** The captured bytes. */
  bytes: Uint8Array;
}

/** A fully dissected packet, ready for the UI. */
export interface DissectedPacket extends RawPacket {
  /** Time relative to the first packet in the capture, in seconds. */
  relativeTime: number;
  /** Ordered protocol headers, outermost first. */
  protocols: ProtocolLayer[];
  /** Highest-layer protocol abbreviation, shown in the "Protocol" column. */
  protocol: string;
  /** Best available source address (IP if present, otherwise MAC). */
  source: string;
  /** Best available destination address. */
  destination: string;
  /** Wireshark-style one-line description. */
  info: string;
  /** Flattened, deduplicated set of addresses/ports for the quick filter. */
  searchIndex: string;
  /** Non-fatal dissection problems (truncated packet, bad length, ...). */
  warnings: string[];
}

/** The result of reading a whole capture file. */
export interface Capture {
  fileName: string;
  fileSize: number;
  meta: CaptureMeta;
  packets: DissectedPacket[];
  warnings: string[];
}

export const LAYER_NAMES: Record<OsiLayer, string> = {
  1: 'Physical',
  2: 'Data Link',
  3: 'Network',
  4: 'Transport',
  5: 'Session',
  6: 'Presentation',
  7: 'Application',
};

/** The PDU name each layer gives to the thing it hands to its neighbour. */
export const LAYER_PDU: Record<OsiLayer, string> = {
  1: 'Bits / Symbols',
  2: 'Frame',
  3: 'Packet',
  4: 'Segment / Datagram',
  5: 'Data',
  6: 'Data',
  7: 'Data',
};
