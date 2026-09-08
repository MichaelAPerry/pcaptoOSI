/** DHCP / BOOTP dissection, including the option TLV list. */

import type { Field } from '../types';
import { DissectContext, field } from './context';
import { formatIPv4, formatMac, hex, hexPreview, readU32BE } from '../bytes';

const MESSAGE_TYPES: Record<number, string> = {
  1: 'DISCOVER',
  2: 'OFFER',
  3: 'REQUEST',
  4: 'DECLINE',
  5: 'ACK',
  6: 'NAK',
  7: 'RELEASE',
  8: 'INFORM',
};

const OPTION_NAMES: Record<number, string> = {
  1: 'Subnet Mask',
  3: 'Router (default gateway)',
  6: 'Domain Name Server',
  12: 'Host Name',
  15: 'Domain Name',
  28: 'Broadcast Address',
  50: 'Requested IP Address',
  51: 'IP Address Lease Time',
  53: 'DHCP Message Type',
  54: 'DHCP Server Identifier',
  55: 'Parameter Request List',
  57: 'Maximum DHCP Message Size',
  58: 'Renewal (T1) Time',
  59: 'Rebinding (T2) Time',
  60: 'Vendor Class Identifier',
  61: 'Client Identifier',
  82: 'Relay Agent Information',
  119: 'Domain Search List',
};

function describeMessageType(t: number): string {
  switch (t) {
    case 1:
      return 'DISCOVER is the "D" of DORA. The client has no address yet, so it broadcasts from 0.0.0.0 to 255.255.255.255 hoping some server on the segment answers. This is why DHCP relay agents exist: broadcasts do not cross routers.';
    case 2:
      return 'OFFER is the "O". A server proposes an address and the parameters that go with it. More than one server may offer; the client picks one.';
    case 3:
      return 'REQUEST is the "R". The client formally asks for one specific offer, broadcast so the servers it did not choose can withdraw their offers.';
    case 5:
      return 'ACK is the "A". The lease is now binding, and the client may start using the address.';
    case 6:
      return 'NAK: the server refuses — usually because the client asked for an address that belongs to a different subnet, e.g. after moving to a new network.';
    case 7:
      return 'RELEASE: the client is giving the lease back early.';
    default:
      return 'A DHCP message.';
  }
}

export function looksLikeDhcp(ctx: DissectContext, offset: number, length: number): boolean {
  return length >= 240 && ctx.has(offset + 236, 4) && readU32BE(ctx.bytes, offset + 236) === 0x63825363;
}

export function dissectDhcp(ctx: DissectContext, offset: number, length: number): void {
  const b = ctx.bytes;
  const limit = Math.min(b.length, offset + length);
  if (limit - offset < 240) return;

  const op = b[offset];
  const xid = readU32BE(b, offset + 4);
  const ciaddr = formatIPv4(b, offset + 12);
  const yiaddr = formatIPv4(b, offset + 16);
  const siaddr = formatIPv4(b, offset + 20);
  const giaddr = formatIPv4(b, offset + 24);
  const chaddr = formatMac(b, offset + 28);

  ctx.term('dhcp', 'bootp', chaddr, yiaddr);

  const fields: Field[] = [
    field({
      name: 'Message op code',
      value: `${op} (${op === 1 ? 'BOOTREQUEST' : 'BOOTREPLY'})`,
      offset,
      length: 1,
      layer: 7,
      key: 'dhcp.op',
    }),
    field({ name: 'Hardware type', value: `${b[offset + 1]}${b[offset + 1] === 1 ? ' (Ethernet)' : ''}`, offset: offset + 1, length: 1, layer: 7, whatText: 'The link-layer type the client is using.' }),
    field({ name: 'Hardware address length', value: String(b[offset + 2]), offset: offset + 2, length: 1, layer: 7, whatText: '6 for an Ethernet MAC.' }),
    field({ name: 'Hops', value: String(b[offset + 3]), offset: offset + 3, length: 1, layer: 7, whatText: 'Incremented by each relay agent that forwards this message off the local segment.' }),
    field({
      name: 'Transaction ID',
      value: hex(xid, 8),
      offset: offset + 4,
      length: 4,
      layer: 7,
      key: 'dhcp.xid',
      why: 'All four DORA messages carry this same value. Since the client has no IP address yet, the transaction ID and its MAC are the only things tying the exchange together.',
    }),
    field({ name: 'Seconds elapsed', value: String((b[offset + 8] << 8) | b[offset + 9]), offset: offset + 8, length: 2, layer: 7, whatText: 'How long the client has been trying to get an address. Relay agents use it to decide when to step in.' }),
    field({
      name: 'Flags',
      value: (b[offset + 10] & 0x80) === 0x80 ? 'broadcast' : 'unicast',
      offset: offset + 10,
      length: 2,
      layer: 7,
      whatText: 'Only the top bit is defined: it asks the server to broadcast its reply, for clients whose IP stack cannot receive a unicast packet before it has an address.',
    }),
    field({ name: 'Client IP address (ciaddr)', value: ciaddr, offset: offset + 12, length: 4, layer: 7, whatText: 'Filled in only when the client already has a working address, e.g. when renewing a lease.' }),
    field({
      name: 'Your IP address (yiaddr)',
      value: yiaddr,
      offset: offset + 16,
      length: 4,
      layer: 7,
      key: 'dhcp.yiaddr',
      why: yiaddr === '0.0.0.0' ? 'Zero in a client message: the client has nothing to offer here.' : `The server is assigning ${yiaddr} to this client.`,
    }),
    field({ name: 'Next server IP (siaddr)', value: siaddr, offset: offset + 20, length: 4, layer: 7, whatText: 'The TFTP server to boot from, used by PXE network boot.' }),
    field({ name: 'Relay agent IP (giaddr)', value: giaddr, offset: offset + 24, length: 4, layer: 7, whatText: 'Set by a relay agent so the server knows which subnet the request came from — and therefore which pool to allocate from.' }),
    field({
      name: 'Client hardware address (chaddr)',
      value: chaddr,
      offset: offset + 28,
      length: 6,
      layer: 7,
      key: 'dhcp.chaddr',
      why: 'The server keys its lease database on this MAC, which is how you get the same address back after a reboot. It is also why MAC randomisation on phones produces a new lease every time.',
    }),
    field({
      name: 'Magic cookie',
      value: hex(readU32BE(b, offset + 236), 8),
      offset: offset + 236,
      length: 4,
      layer: 7,
      key: 'dhcp.magic',
      why: 'DHCP was defined as an extension of the older BOOTP protocol. This constant marks the point where BOOTP\'s fixed fields end and DHCP\'s options begin.',
    }),
  ];

  let messageType = 0;
  const optionFields: Field[] = [];
  let o = offset + 240;
  let guard = 0;

  while (o < limit && guard++ < 128) {
    const code = b[o];
    if (code === 255) {
      optionFields.push(field({ name: 'End option (255)', value: 'end of options', offset: o, length: 1, layer: 7, whatText: 'Marks the end of the option list; anything after it is padding.' }));
      break;
    }
    if (code === 0) {
      o += 1;
      continue;
    }
    const len = b[o + 1] ?? 0;
    if (o + 2 + len > limit) break;
    const name = OPTION_NAMES[code] ?? `Option ${code}`;
    let value = hexPreview(b, o + 2, len);
    let why: string | undefined;

    switch (code) {
      case 53:
        messageType = b[o + 2];
        value = `${messageType} (${MESSAGE_TYPES[messageType] ?? 'unknown'})`;
        why = describeMessageType(messageType);
        break;
      case 1:
      case 3:
      case 6:
      case 28:
      case 50:
      case 54: {
        const addrs: string[] = [];
        for (let i = 0; i + 4 <= len; i += 4) addrs.push(formatIPv4(b, o + 2 + i));
        value = addrs.join(', ');
        if (code === 1) why = 'The subnet mask tells the client which addresses it can reach directly on the link and which need the gateway — the single most important piece of routing knowledge a host has.';
        if (code === 3) why = 'The default gateway: where the client sends anything that is not on its own subnet.';
        if (code === 6) why = 'The resolvers this client will use. Control of this option is control of the client\'s view of the Internet, which is why rogue DHCP servers are so dangerous.';
        break;
      }
      case 51:
      case 58:
      case 59: {
        const seconds = readU32BE(b, o + 2);
        value = `${seconds} seconds (${(seconds / 3600).toFixed(1)} hours)`;
        if (code === 51) why = 'The client must renew before this expires or stop using the address. Renewal is normally attempted at half the lease time (T1).';
        break;
      }
      case 12:
      case 15:
      case 60: {
        let s = '';
        for (let i = 0; i < len; i++) s += String.fromCharCode(b[o + 2 + i]);
        value = s;
        if (code === 60) why = 'The vendor class string often identifies the device type outright — "MSFT 5.0", "android-dhcp-14", "PXEClient" — which is why it is a favourite for device fingerprinting and for steering PXE boot.';
        break;
      }
      case 55: {
        const requested: string[] = [];
        for (let i = 0; i < len; i++) requested.push(OPTION_NAMES[b[o + 2 + i]] ?? String(b[o + 2 + i]));
        value = requested.join(', ');
        why = 'The exact list, and its order, is characteristic of the client operating system — the DHCP equivalent of a JA3 fingerprint.';
        break;
      }
      default:
        break;
    }

    optionFields.push(
      field({
        name: `${name} (${code})`,
        value,
        offset: o,
        length: 2 + len,
        layer: 7,
        key: code === 53 ? 'dhcp.msgtype' : 'dhcp.option',
        why,
      }),
    );
    o += 2 + len;
  }

  fields.push(
    field({
      name: `Options (${optionFields.length})`,
      value: MESSAGE_TYPES[messageType] ?? 'BOOTP only',
      offset: offset + 240,
      length: Math.max(0, Math.min(o + 1, limit) - (offset + 240)),
      layer: 7,
      key: 'dhcp.option',
      children: optionFields,
    }),
  );

  const typeName = MESSAGE_TYPES[messageType] ?? 'BOOTP';
  ctx.term(typeName.toLowerCase());

  ctx.add({
    id: 'dhcp',
    name: 'Dynamic Host Configuration Protocol',
    abbr: 'DHCP',
    layer: 7,
    summary: `${typeName}${yiaddr !== '0.0.0.0' ? ` — ${yiaddr}` : ''} (xid ${hex(xid, 8)})`,
    offset,
    length: Math.max(240, Math.min(o + 1, limit) - offset),
    fields,
  });

  ctx.info = `DHCP ${typeName} - Transaction ID ${hex(xid, 8)}`;

  ctx.add({
    id: 'dhcp-session',
    name: 'Session layer (DHCP transaction)',
    abbr: 'DHCP',
    layer: 5,
    virtual: true,
    summary: `Transaction ${hex(xid, 8)} spans the whole DORA exchange`,
    offset,
    length: 0,
    fields: [
      field({
        name: 'Transaction identifier',
        value: hex(xid, 8),
        offset: offset + 4,
        length: 4,
        layer: 5,
        key: 'dhcp.xid',
        why: 'Four separate UDP broadcasts, no connection anywhere, and yet they form one logical exchange. That correlation is a session — built by the application because UDP offers none.',
      }),
    ],
  });
}
