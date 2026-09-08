/**
 * The teaching dictionary.
 *
 * Every header field the dissector emits carries a key into this table. The
 * text answers the first half of the "Teacher Mode" question — *what is this
 * field for* — in plain English, without assuming the reader already knows
 * the protocol. The second half — *why does this particular value matter* --
 * is computed per packet by the dissectors, because it depends on the bytes.
 *
 * Keeping the static half here means one place to proofread, and it keeps the
 * dissectors readable.
 */

export const GLOSSARY: Record<string, string> = {
  /* ------------------------------------------------------------ Layer 1 — */
  'frame.arrival':
    'The moment the capture driver stamped this frame as it arrived. Timestamps come from the capturing host, not from the packet itself, so two machines capturing the same conversation will disagree slightly.',
  'frame.delta':
    'Time since the previous packet in this capture. Gaps are how you spot retransmission timers, application think-time and slow DNS.',
  'frame.caplen':
    'How many bytes of this frame the capture tool actually wrote to disk. Anything beyond the snapshot length is discarded before it ever reaches the file.',
  'frame.wirelen':
    'How many bytes were really on the wire, as reported by the driver. When this is larger than the captured length, you are looking at a truncated (sliced) frame.',
  'frame.iface':
    'Which capture interface this frame came in on. pcapng files can interleave several interfaces in one capture; classic pcap files always have exactly one.',
  'frame.linktype':
    'The link-layer encapsulation the capture uses, e.g. Ethernet. It tells the dissector how to interpret byte zero of the frame.',
  'frame.number':
    'The position of this record in the capture file. It is assigned by the capture tool, not carried on the wire.',
  'frame.physical':
    'Everything that happens below the frame — preamble, start-of-frame delimiter, line coding, voltage or RF modulation, and usually the Ethernet FCS trailer — is consumed and stripped by the network adapter before the capture driver ever sees the frame. A PCAP file therefore begins at the first byte of Layer 2. What you can still learn about Layer 1 is the metadata around the frame: when it arrived, how big it really was, and which physical port carried it.',
  'frame.fcs':
    'The 4-byte Frame Check Sequence that Ethernet appends to every frame. Adapters verify and remove it in hardware, so it is almost never present in a capture file. A frame with a bad FCS is normally dropped by the NIC and never reaches you at all.',

  /* ------------------------------------------------------------ Layer 2 — */
  'eth.dst':
    'The hardware (MAC) address of the next hop on this physical segment. It is rewritten at every router, so it only ever tells you about the local link.',
  'eth.src':
    'The MAC address of the interface that put this frame on the wire. The first three bytes are the OUI, which identifies the hardware vendor.',
  'eth.type':
    'EtherType: which Layer 3 protocol is inside this frame. 0x0800 is IPv4, 0x86DD is IPv6, 0x0806 is ARP, 0x8100 is a VLAN tag.',
  'eth.len':
    'In IEEE 802.3 framing, values of 1500 or below in this position are a length, not an EtherType, and an LLC/SNAP header follows.',
  'eth.padding':
    'Ethernet requires a minimum payload of 46 bytes. Short packets are padded with zeroes, which is why a 20-byte ARP payload arrives in a 60-byte frame.',
  'vlan.pcp':
    'Priority Code Point: the 802.1p class of service, 0-7. Switches use it to decide which queue the frame goes into when a port is congested.',
  'vlan.dei':
    'Drop Eligible Indicator (formerly CFI). When set, this frame may be dropped first if the switch has to shed load.',
  'vlan.id':
    'The VLAN this frame belongs to, 1-4094. VLAN 1 is the default; 0 means "priority tagged only", with no VLAN membership.',
  'vlan.type':
    'The EtherType of whatever follows the VLAN tag — often another VLAN tag in a QinQ stack.',

  'arp.htype': 'Hardware type of the network being resolved on. 1 means Ethernet.',
  'arp.ptype': 'Protocol type being resolved. 0x0800 means we are asking about an IPv4 address.',
  'arp.hlen': 'Length of a hardware address, in bytes. 6 for Ethernet MACs.',
  'arp.plen': 'Length of a protocol address, in bytes. 4 for IPv4.',
  'arp.op':
    'Operation code: 1 = request ("who has this IP?"), 2 = reply ("I do, here is my MAC"). ARP has no session and no acknowledgement — the reply is simply another broadcast-capable frame.',
  'arp.sha': 'Sender hardware address: the MAC of the station that generated this ARP message.',
  'arp.spa': 'Sender protocol address: the IPv4 address the sender claims to own.',
  'arp.tha':
    'Target hardware address. In a request this is all zeroes, because finding it out is the entire point of the request.',
  'arp.tpa': 'Target protocol address: the IPv4 address whose MAC we want.',

  /* ------------------------------------------------------------ Layer 3 — */
  'ip.version': 'IP version number. 4 for IPv4, 6 for IPv6. It is the first nibble of the packet.',
  'ip.ihl':
    'Internet Header Length, counted in 32-bit words. The minimum is 5 (20 bytes); anything larger means IP options are present.',
  'ip.dscp':
    'Differentiated Services Code Point: the QoS class. 46 (EF) is expedited forwarding for voice, 0 is best effort.',
  'ip.ecn':
    'Explicit Congestion Notification. Routers can set this to 3 (CE) to signal congestion instead of dropping the packet, letting TCP slow down without a loss event.',
  'ip.totallen':
    'Total length of the IP header plus everything it carries, in bytes. This, not the Ethernet frame size, is the authoritative length of the packet.',
  'ip.id':
    'Identification: a value shared by all fragments of the same original datagram, so the receiver can reassemble them. Some stacks also make it predictable, which is a fingerprinting and idle-scan risk.',
  'ip.flags':
    'Three control bits governing fragmentation: reserved, Don\'t Fragment, and More Fragments.',
  'ip.flag.df':
    'Don\'t Fragment. When set, a router that cannot forward the packet without splitting it must drop it and return ICMP "Fragmentation Needed". This is how Path MTU Discovery works — and when the ICMP is firewalled, how PMTU black holes happen.',
  'ip.flag.mf':
    'More Fragments. Set on every fragment except the last, so the receiver knows the datagram is incomplete.',
  'ip.fragoffset':
    'Where this fragment sits in the original datagram, counted in 8-byte units. A non-zero value means you are looking at a piece, not a whole packet.',
  'ip.ttl':
    'Time To Live: decremented by one at every router. At zero the packet is discarded and an ICMP Time Exceeded is returned — which is exactly the mechanism traceroute exploits.',
  'ip.proto':
    'Which Layer 4 protocol is inside: 1 = ICMP, 6 = TCP, 17 = UDP, 47 = GRE, 50 = ESP.',
  'ip.checksum':
    'A checksum over the IPv4 header only, not the payload. Every router must recompute it because it changes the TTL. IPv6 removed this field entirely to save that work.',
  'ip.src': 'The IPv4 address of the original sender. Unlike the MAC address, it survives every router hop.',
  'ip.dst': 'The IPv4 address of the final recipient. Routers forward on this field and never change it (barring NAT).',
  'ip.options': 'Optional IPv4 header extensions such as Record Route or Timestamp. Rare in practice, and often dropped by routers.',

  'ip6.version': 'IP version, 6.',
  'ip6.tclass': 'Traffic Class: the IPv6 equivalent of IPv4 DSCP + ECN, carrying QoS and congestion marking.',
  'ip6.flow':
    'Flow Label: lets routers identify packets belonging to the same flow without digging into the transport header, which is useful for equal-cost load balancing.',
  'ip6.plen':
    'Payload Length: bytes after the fixed 40-byte header. Note the difference from IPv4, where the length field includes the header.',
  'ip6.nexthdr':
    'Next Header: either a Layer 4 protocol number or an IPv6 extension header type. Extension headers chain, so this may need following several times.',
  'ip6.hoplimit': 'The IPv6 name for TTL. Same job: decremented at each router, packet dies at zero.',
  'ip6.src': 'Source IPv6 address (128 bits). fe80::/10 is link-local, 2000::/3 is global unicast, ff00::/8 is multicast.',
  'ip6.dst': 'Destination IPv6 address (128 bits).',

  /* ------------------------------------------------------------ Layer 4 — */
  'tcp.sport':
    'Source port. Together with the destination port and both IP addresses it forms the four-tuple that uniquely identifies this connection.',
  'tcp.dport':
    'Destination port: which service on the far host this segment is for. 80 = HTTP, 443 = HTTPS, 22 = SSH, 53 = DNS.',
  'tcp.seq':
    'Sequence number: the position of the first payload byte in this segment within the sender\'s byte stream. It starts at a random Initial Sequence Number to make blind injection hard.',
  'tcp.ack':
    'Acknowledgement number: the next sequence number the sender expects to receive. It is cumulative — acknowledging byte N implicitly acknowledges everything before it.',
  'tcp.offset':
    'Data Offset: the TCP header length in 32-bit words. 5 means a bare 20-byte header; more means TCP options are present.',
  'tcp.flags': 'The nine control bits that drive the TCP state machine.',
  'tcp.flag.ns': 'Nonce Sum, part of the (rarely deployed) ECN nonce mechanism.',
  'tcp.flag.cwr': 'Congestion Window Reduced: the sender is telling its peer it has responded to an ECN congestion signal.',
  'tcp.flag.ece': 'ECN-Echo: during the handshake it advertises ECN support; afterwards it reflects a congestion mark back to the sender.',
  'tcp.flag.urg': 'Urgent: the Urgent Pointer field is meaningful. Effectively obsolete, and a classic firewall-evasion trick.',
  'tcp.flag.ack': 'Acknowledgement field is valid. Set on every segment after the very first SYN.',
  'tcp.flag.psh': 'Push: deliver this data to the application now rather than waiting for the buffer to fill.',
  'tcp.flag.rst': 'Reset: tear this connection down immediately. Sent when a port is closed, a state is lost, or a middlebox is blocking traffic.',
  'tcp.flag.syn': 'Synchronise: this segment carries an Initial Sequence Number. Only the first two segments of a connection have it set.',
  'tcp.flag.fin': 'Finish: the sender has no more data. Each direction closes independently, which is why a clean teardown takes three or four segments.',
  'tcp.window':
    'Receive Window: how many more bytes the sender of this segment is willing to accept. A window of zero means "stop sending, my buffer is full".',
  'tcp.checksum':
    'Covers the TCP header, the payload, and a pseudo-header built from the IP addresses — which is how TCP notices if a packet was delivered to the wrong address.',
  'tcp.urgptr': 'Offset to the end of urgent data, meaningful only when the URG flag is set.',
  'tcp.options': 'TCP options negotiated in the handshake or used per segment: MSS, window scaling, SACK, timestamps.',
  'tcp.opt.mss':
    'Maximum Segment Size: the largest payload this host will accept in one segment. 1460 is the classic value for a 1500-byte Ethernet MTU.',
  'tcp.opt.wscale':
    'Window Scale: multiplies the 16-bit window field by 2^N, lifting the ceiling above 64 KiB. It can only be negotiated in the handshake, which is why a capture missing the SYN shows nonsense window sizes.',
  'tcp.opt.sackperm': 'SACK Permitted: advertises that this host can acknowledge non-contiguous blocks, so a single loss does not stall the whole stream.',
  'tcp.opt.sack': 'Selective Acknowledgement: the exact byte ranges that did arrive, letting the sender retransmit only the hole.',
  'tcp.opt.ts': 'Timestamps: used for round-trip time measurement and for protection against wrapped sequence numbers on fast links.',
  'tcp.opt.nop': 'No-Operation: a one-byte filler used to align the following option on a 4-byte boundary.',
  'tcp.opt.eol': 'End of Option List.',

  'udp.sport': 'Source port. UDP has no connection, so this is simply where replies should be sent.',
  'udp.dport': 'Destination port: which service this datagram is for. 53 = DNS, 67/68 = DHCP, 123 = NTP, 443 = QUIC.',
  'udp.length': 'Length of the UDP header plus payload, in bytes. The 8-byte header is the minimum.',
  'udp.checksum':
    'Optional in IPv4 (zero means "not computed"), mandatory in IPv6. Like TCP it covers a pseudo-header of the IP addresses.',

  'icmp.type': 'What kind of ICMP message this is: 8 = Echo Request, 0 = Echo Reply, 3 = Destination Unreachable, 11 = Time Exceeded.',
  'icmp.code': 'A sub-type that refines the meaning, e.g. type 3 code 4 is "fragmentation needed but DF set".',
  'icmp.checksum': 'Checksum over the whole ICMP message, header and data together.',
  'icmp.id': 'Identifier used to match replies to requests. Typically the sending process ID, or rewritten by NAT.',
  'icmp.seq': 'Sequence number, incremented per ping so you can spot loss and reordering.',
  'icmp.data': 'Payload the sender chose. Ping tools fill it with a timestamp and a fixed pattern; the responder must echo it back verbatim.',
  'icmp6.type': 'ICMPv6 message type. 128/129 are Echo Request/Reply; 133-137 are Neighbour Discovery, which replaces ARP.',

  /* ------------------------------------------------------------ Layer 5 — */
  'session.model':
    'In the strict OSI model, Layer 5 establishes, manages and tears down dialogues between applications: it owns checkpoints, dialogue control and session recovery. The TCP/IP stack that actually runs the Internet has no separate session protocol — these duties are absorbed by the transport layer (the TCP connection) and by the application protocol itself.',
  'session.tcp':
    'The TCP connection is what plays the session role here. The four-tuple of addresses and ports is the session identifier, the handshake is session establishment, and FIN/RST is session termination.',
  'tls.session_id':
    'A TLS session identifier. In TLS 1.2 this is genuine Layer 5 state: presenting a known ID lets a client resume an earlier session and skip the expensive key exchange. In TLS 1.3 the field is legacy — it is echoed for middlebox compatibility and resumption is done with tickets instead.',
  'tls.ticket': 'A session ticket: encrypted session state handed to the client so the server does not have to remember anything. Presenting it later resumes the session.',
  'dns.txid': 'The DNS transaction ID, which correlates a response with its query. It is the only session state a stateless UDP exchange has — and guessing it is the basis of cache-poisoning attacks.',
  'http.session':
    'HTTP is stateless by design, so any notion of a session is layered on top: a Cookie header, an Authorization token, or simply the lifetime of the underlying TCP connection.',
  'http.keepalive':
    'Connection: keep-alive keeps the TCP connection open for further requests. This is the closest HTTP/1.1 gets to an explicit session-layer construct.',

  /* ------------------------------------------------------------ Layer 6 — */
  'presentation.model':
    'Layer 6 is about representation rather than delivery: character sets, data structure encoding, compression and encryption. In the TCP/IP world these duties are spread between TLS (encryption), content encodings such as gzip, and the serialisation the application chose (JSON, ASN.1, protobuf).',
  'tls.record.type':
    'TLS content type: 22 = handshake, 20 = change cipher spec, 21 = alert, 23 = application data. This is the outermost framing of every TLS record.',
  'tls.record.version':
    'The record-layer version. For compatibility with old middleboxes, modern clients pin this to TLS 1.0 (0x0301) in the first record and negotiate the real version inside the handshake.',
  'tls.record.length': 'Length of the encrypted or plaintext record that follows, up to 16 KiB.',
  'tls.handshake.type':
    'Which handshake message this is: 1 = ClientHello, 2 = ServerHello, 11 = Certificate, 16 = ClientKeyExchange, 20 = Finished.',
  'tls.version':
    'The protocol version being offered or selected. TLS 1.3 hides the real version in the supported_versions extension and leaves this field reading 1.2.',
  'tls.random':
    '32 bytes of client or server randomness mixed into the key schedule, guaranteeing that two sessions with the same keys still derive different secrets.',
  'tls.ciphersuites':
    'The ordered list of cipher suites the client is willing to use. The server picks one. Their exact set and order is a highly effective client fingerprint (JA3).',
  'tls.ciphersuite': 'A single cipher suite: key exchange, authentication, bulk cipher and MAC, encoded as one 16-bit number.',
  'tls.compression':
    'Legacy TLS compression. It must be "null" — compressing before encrypting enabled the CRIME attack, so TLS 1.3 removed the field\'s meaning entirely.',
  'tls.extensions': 'Extensions carry everything modern TLS actually negotiates: SNI, ALPN, supported groups, key shares, versions.',
  'tls.ext.sni':
    'Server Name Indication: the hostname the client wants, sent in the clear so one IP can host many certificates. It is also the single most useful field in an encrypted capture, because it tells you where the traffic is going.',
  'tls.ext.alpn':
    'Application-Layer Protocol Negotiation: which Layer 7 protocol will run inside the tunnel, e.g. "h2" for HTTP/2 or "http/1.1".',
  'tls.ext.versions': 'supported_versions: the real version list in TLS 1.3. If it contains 0x0304, this is a TLS 1.3 handshake regardless of what the legacy version fields say.',
  'tls.ext.keyshare': 'key_share: the client\'s ephemeral Diffie-Hellman public key, sent up front so TLS 1.3 can finish in one round trip.',
  'tls.ext.groups': 'supported_groups: which elliptic curves or finite-field groups the client can do key exchange with.',
  'http.content_type':
    'The MIME type of the body — the canonical Layer 6 field. It tells the receiver how to interpret the bytes: text/html, application/json, image/png.',
  'http.charset': 'The character encoding of a textual body. Getting this wrong is what produces mojibake.',
  'http.content_encoding':
    'A compression codec applied to the body (gzip, br, deflate). The receiver must undo it before the bytes mean anything — a Layer 6 transformation.',
  'http.transfer_encoding':
    'How the body is framed on the connection. "chunked" sends length-prefixed pieces so a response can start before its total size is known.',

  /* ------------------------------------------------------------ Layer 7 — */
  'http.method': 'The HTTP verb: GET reads, POST submits, PUT replaces, DELETE removes. GET and HEAD are supposed to be safe and side-effect free.',
  'http.uri': 'The resource being requested, relative to the host. Query parameters after "?" travel in the clear over plain HTTP.',
  'http.version': 'HTTP protocol version. 1.1 added persistent connections, Host, and chunked encoding.',
  'http.status': 'The response status code: 2xx success, 3xx redirect, 4xx client error, 5xx server error.',
  'http.reason': 'A human-readable phrase accompanying the status code. Purely decorative; clients act on the number.',
  'http.header': 'One HTTP header field. Headers are the extensibility mechanism of HTTP — almost everything beyond method and URI lives here.',
  'http.host': 'Which virtual host the request is for. Mandatory in HTTP/1.1, and the plaintext equivalent of TLS SNI.',
  'http.useragent': 'A self-declared description of the client software. Trivially forged, but useful for spotting bots and old browsers.',
  'http.body': 'The message body: the actual document, form submission or API payload.',

  'dns.flags': 'The 16 bits that describe what kind of DNS message this is and how it should be handled.',
  'dns.flag.qr': 'Query (0) or Response (1).',
  'dns.flag.opcode': 'Operation code: 0 = standard query, 4 = notify, 5 = dynamic update.',
  'dns.flag.aa': 'Authoritative Answer: this response came from a server that actually owns the zone, not from a cache.',
  'dns.flag.tc': 'Truncated: the response did not fit in the UDP datagram. The client is expected to retry over TCP.',
  'dns.flag.rd': 'Recursion Desired: the client is asking the server to chase the answer down for it.',
  'dns.flag.ra': 'Recursion Available: this server is willing to do that.',
  'dns.flag.rcode': 'Result code: 0 = no error, 2 = server failure, 3 = NXDOMAIN (the name does not exist).',
  'dns.counts': 'How many records are in each of the four sections that follow the header.',
  'dns.qname': 'The domain name being asked about, encoded as a series of length-prefixed labels terminated by a zero byte.',
  'dns.qtype': 'The record type wanted: 1 = A, 28 = AAAA, 5 = CNAME, 15 = MX, 16 = TXT, 12 = PTR.',
  'dns.qclass': 'The address family. In practice always 1 (IN, the Internet class).',
  'dns.rr': 'A resource record in the answer, authority or additional section.',
  'dns.ttl': 'How long, in seconds, a resolver may cache this record. Short TTLs mean fast failover and more query traffic.',
  'dns.rdata': 'The record\'s payload — an IP address for A/AAAA, another name for CNAME, and so on.',
  'dns.compression':
    'DNS name compression: a pointer back to a name earlier in the message, so a repeated domain costs two bytes instead of twenty.',

  'dhcp.op': 'Message direction: 1 = BOOTREQUEST (client to server), 2 = BOOTREPLY.',
  'dhcp.xid': 'Transaction ID tying a DORA exchange together across four separate broadcast messages.',
  'dhcp.yiaddr': '"Your" IP address — the address the server is offering or assigning to the client.',
  'dhcp.chaddr': 'Client hardware address. The DHCP server keys its leases on this MAC.',
  'dhcp.magic': 'The magic cookie 0x63825363 that marks the start of DHCP options inside the older BOOTP frame.',
  'dhcp.option': 'A DHCP option in type-length-value form. Option 53 is the message type, 1 the subnet mask, 3 the router, 6 the DNS servers.',
  'dhcp.msgtype': 'Which step of the DORA exchange this is: 1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK, 7 Release.',

  'payload.raw':
    'The remaining application bytes. When no dissector recognises the protocol, the safest thing an analyst can do is read the hex and the ASCII side by side.',
  'payload.encrypted':
    'Encrypted application data. Everything above the transport layer is opaque here by design — what you can still learn comes from the metadata: who talked to whom, when, how much, and in what pattern.',
};

export function what(key: string, fallback = ''): string {
  return GLOSSARY[key] ?? fallback;
}
