/**
 * A deliberately small OUI table.
 *
 * The point is pedagogical, not exhaustive: students should learn that the
 * first three bytes of a MAC identify the vendor, and that a locally
 * administered address (the U/L bit set) means the address was made up by
 * software — a VM, a container, or a phone doing MAC randomisation.
 */
const OUI: Record<string, string> = {
  '000C29': 'VMware',
  '005056': 'VMware',
  '001C14': 'VMware',
  '080027': 'Oracle VirtualBox',
  '525400': 'QEMU / KVM virtual NIC',
  '0242AC': 'Docker bridge',
  '00155D': 'Microsoft Hyper-V',
  'B827EB': 'Raspberry Pi Foundation',
  'DCA632': 'Raspberry Pi Trading',
  '001A2B': 'Ayecom / generic',
  '3C0754': 'Apple',
  'F0189E': 'Apple',
  'ACBC32': 'Apple',
  '001B63': 'Apple',
  '00005E': 'IANA (VRRP / virtual router)',
  'FCECDA': 'Ubiquiti',
  '245A4C': 'Ubiquiti',
  '0018E7': 'Cisco',
  '00000C': 'Cisco',
  '001A6D': 'Cisco',
  'C0C1C0': 'Cisco-Linksys',
  '001517': 'Intel',
  '3497F6': 'ASUSTek',
  'E45F01': 'Raspberry Pi',
};

export function ouiVendor(mac: string): string | undefined {
  const key = mac.replace(/[:-]/g, '').slice(0, 6).toUpperCase();
  return OUI[key];
}

/** Human description of the special bits in the first byte of a MAC address. */
export function macNature(mac: string): { kind: string; detail: string } {
  const normalised = mac.toLowerCase();
  if (normalised === 'ff:ff:ff:ff:ff:ff') {
    return {
      kind: 'broadcast',
      detail:
        'This is the Ethernet broadcast address: every station on the local segment must receive and process this frame. Broadcasts stop at the first router, which is exactly what defines a broadcast domain.',
    };
  }
  const first = parseInt(normalised.slice(0, 2), 16);
  if (Number.isNaN(first)) return { kind: 'unknown', detail: '' };
  const multicast = (first & 0x01) === 1;
  const local = (first & 0x02) === 2;
  if (multicast) {
    if (normalised.startsWith('01:00:5e')) {
      return {
        kind: 'IPv4 multicast',
        detail:
          'The 01:00:5e prefix means this is a MAC derived from an IPv4 multicast group address — the low 23 bits of the group are copied straight into the MAC.',
      };
    }
    if (normalised.startsWith('33:33')) {
      return {
        kind: 'IPv6 multicast',
        detail:
          'The 33:33 prefix marks an IPv6 multicast MAC; the last 32 bits of the IPv6 multicast address are copied into it. Neighbour Discovery uses these instead of ARP broadcasts.',
      };
    }
    if (normalised.startsWith('01:80:c2')) {
      return {
        kind: 'IEEE 802.1D reserved',
        detail: 'Reserved for spanning tree and other link-layer control protocols, which bridges never forward.',
      };
    }
    return {
      kind: 'multicast',
      detail:
        'The low bit of the first byte is set, which marks a multicast address: switches flood it to a group of listeners rather than to a single port.',
    };
  }
  if (local) {
    return {
      kind: 'locally administered unicast',
      detail:
        'The second-lowest bit of the first byte is set, meaning this address was assigned by software rather than burned in by a manufacturer — typical of virtual machines, containers, and phones doing MAC randomisation.',
    };
  }
  return {
    kind: 'globally unique unicast',
    detail: 'A normal burned-in address: the first three bytes are the manufacturer OUI, the last three are the serial part.',
  };
}
