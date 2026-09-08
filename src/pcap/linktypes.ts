/** libpcap LINKTYPE_* numbers we know how to name, and the subset we dissect. */
export const LINK_TYPES: Record<number, string> = {
  0: 'NULL / BSD loopback',
  1: 'Ethernet (IEEE 802.3)',
  6: 'IEEE 802.5 Token Ring',
  8: 'SLIP',
  9: 'PPP',
  101: 'Raw IP',
  105: 'IEEE 802.11 wireless',
  113: 'Linux cooked capture (SLL)',
  127: 'IEEE 802.11 + radiotap header',
  204: 'PPP with HDLC framing',
  228: 'Raw IPv4',
  229: 'Raw IPv6',
  276: 'Linux cooked capture v2 (SLL2)',
};

export function linkTypeName(n: number): string {
  return LINK_TYPES[n] ?? `Unknown link type ${n}`;
}

/** Link types the dissector can decode end to end. */
export const SUPPORTED_LINK_TYPES = new Set([0, 1, 101, 105, 113, 127, 228, 229, 276]);
