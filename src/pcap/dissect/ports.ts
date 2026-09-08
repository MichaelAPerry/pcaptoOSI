/** Well-known port names, plus the "what kind of port is this" explanation. */

export const PORT_NAMES: Record<number, string> = {
  20: 'FTP-data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP server',
  68: 'DHCP client',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  135: 'MS RPC endpoint mapper',
  137: 'NetBIOS name service',
  138: 'NetBIOS datagram',
  139: 'NetBIOS session service',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP trap',
  179: 'BGP',
  389: 'LDAP',
  443: 'HTTPS / QUIC',
  445: 'SMB',
  465: 'SMTPS',
  514: 'syslog',
  546: 'DHCPv6 client',
  547: 'DHCPv6 server',
  587: 'SMTP submission',
  636: 'LDAPS',
  853: 'DNS over TLS',
  993: 'IMAPS',
  995: 'POP3S',
  1194: 'OpenVPN',
  1433: 'MS SQL Server',
  1521: 'Oracle DB',
  1812: 'RADIUS',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5432: 'PostgreSQL',
  5353: 'mDNS',
  6379: 'Redis',
  8080: 'HTTP alternate',
  8443: 'HTTPS alternate',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
};

export function portName(port: number): string | undefined {
  return PORT_NAMES[port];
}

export function portRangeNote(port: number): string {
  if (port < 1024) {
    return `Port ${port} is in the well-known range (0-1023). On Unix-like systems a process needs root privileges to bind here, which is why the server side of a conversation usually has the low port.`;
  }
  if (port < 49152) {
    return `Port ${port} is in the registered range (1024-49151), assigned by IANA to specific applications.`;
  }
  return `Port ${port} is in the ephemeral range (49152-65535). Operating systems pick these at random for the client side of a connection, so seeing one here tells you which end initiated the conversation.`;
}

/** The lower of the two ports is very often the service; use that for heuristics. */
export function serviceSide(srcPort: number, dstPort: number): number {
  return Math.min(srcPort, dstPort);
}
