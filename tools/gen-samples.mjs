/**
 * Generates the bundled teaching captures.
 *
 * Everything here is synthetic — no real traffic, no real people, no privacy
 * problem in handing the tool to a classroom — but every byte is built to the
 * relevant RFC, with real checksums and real sequence arithmetic, so the
 * captures open correctly in Wireshark and tshark too.
 *
 * Run with: npm run samples
 */

import { writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import {
  arp,
  beaconFixed,
  bytes,
  dnsName,
  dot11,
  dot11Tag,
  DOT11,
  llcSnap,
  radiotap,
  dnsPointer,
  ethernet,
  icmp6Echo,
  icmpEcho,
  ipv4,
  ipv6,
  tcp,
  tcpOptions,
  u16,
  u24,
  u32,
  u8,
  udp,
  writePcap,
  writePcapng,
  TCP_FLAGS,
} from './lib-pcap.mjs';

const { SYN, ACK, PSH, FIN } = TCP_FLAGS;

const CLIENT_MAC = '3c:07:54:1a:2b:3c';
const ROUTER_MAC = 'fc:ec:da:44:55:66';
const SERVER_MAC = '00:0c:29:9a:bb:cc';
const CLIENT_IP = '192.168.1.42';
const ROUTER_IP = '192.168.1.1';
const WEB_IP = '93.184.216.34';
const DNS_IP = '192.168.1.1';

const T0 = Date.UTC(2024, 2, 14, 9, 15, 0) / 1000; // 2024-03-14T09:15:00Z

const samples = [];

function addSample(sample) {
  samples.push(sample);
}

/* ------------------------------------------------------------------ ARP — */
{
  const packets = [
    {
      time: T0,
      data: ethernet(
        'ff:ff:ff:ff:ff:ff',
        CLIENT_MAC,
        0x0806,
        arp({ op: 1, senderMac: CLIENT_MAC, senderIp: CLIENT_IP, targetMac: '00:00:00:00:00:00', targetIp: ROUTER_IP }),
      ),
    },
    {
      time: T0 + 0.000412,
      data: ethernet(
        CLIENT_MAC,
        ROUTER_MAC,
        0x0806,
        arp({ op: 2, senderMac: ROUTER_MAC, senderIp: ROUTER_IP, targetMac: CLIENT_MAC, targetIp: CLIENT_IP }),
      ),
    },
    {
      time: T0 + 1.204,
      data: ethernet(
        'ff:ff:ff:ff:ff:ff',
        ROUTER_MAC,
        0x0806,
        arp({ op: 1, senderMac: ROUTER_MAC, senderIp: ROUTER_IP, targetMac: '00:00:00:00:00:00', targetIp: ROUTER_IP }),
      ),
    },
  ];
  addSample({
    id: 'arp',
    title: 'ARP address resolution',
    layers: 'L2',
    blurb:
      'A host needs the MAC address behind 192.168.1.1, broadcasts the question, and gets a unicast answer. The third frame is a gratuitous ARP — the router announcing itself unprompted.',
    teaches: [
      'ARP carries IP addresses but is not carried inside IP — it stops dead at Layer 2',
      'Why the request goes to ff:ff:ff:ff:ff:ff and the reply does not',
      'Ethernet padding: a 28-byte message inside a 60-byte frame',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* ------------------------------------------------------- ICMP echo (ng) — */
{
  const pingData = Buffer.concat([
    Buffer.from([0x61, 0x2f, 0xf3, 0x65, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x1a, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from(Array.from({ length: 40 }, (_, i) => 0x10 + i)),
  ]);

  const packets = [];
  for (let i = 0; i < 3; i++) {
    const seq = i + 1;
    packets.push({
      time: T0 + i * 1.0,
      data: ethernet(
        ROUTER_MAC,
        CLIENT_MAC,
        0x0800,
        ipv4({
          src: CLIENT_IP,
          dst: WEB_IP,
          protocol: 1,
          id: 0x1c46 + i,
          ttl: 64,
          payload: icmpEcho({ type: 8, id: 0x0a41, seq, data: pingData }),
        }),
      ),
    });
    packets.push({
      time: T0 + i * 1.0 + 0.014337 + i * 0.0004,
      data: ethernet(
        CLIENT_MAC,
        ROUTER_MAC,
        0x0800,
        ipv4({
          src: WEB_IP,
          dst: CLIENT_IP,
          protocol: 1,
          id: 0x0000,
          ttl: 52,
          df: false,
          payload: icmpEcho({ type: 0, id: 0x0a41, seq, data: pingData }),
        }),
      ),
    });
  }

  addSample({
    id: 'icmp',
    title: 'ICMP echo request and reply (ping)',
    layers: 'L3/L4',
    blurb:
      'Three pings and their replies. The replies arrive with TTL 52, so you can count the router hops on the way back and read the round-trip time straight off the timestamps.',
    teaches: [
      'Reading hop count and OS fingerprint from the TTL',
      'How identifier and sequence number match a reply to its request',
      'ICMP sits directly inside IP — there are no ports anywhere in this capture',
      'This file is pcapng rather than classic pcap, so it also exercises the other reader',
    ],
    format: 'pcapng',
    data: writePcapng(packets, { ifName: 'en0', ifDescription: 'Synthetic teaching capture — ICMP echo', comment: 'PCAP-to-OSI sample: ICMP echo request/reply' }),
  });
}

/* ------------------------------------------------------------------ DNS — */
{
  const query = Buffer.concat([
    u16(0x8f21),
    u16(0x0100), // standard query, recursion desired
    u16(1),
    u16(0),
    u16(0),
    u16(0),
    dnsName('www.example.com'),
    u16(1), // A
    u16(1), // IN
  ]);

  // The question name starts at offset 12, so answers can point back to it.
  const answer = Buffer.concat([
    u16(0x8f21),
    u16(0x8180), // response, recursion desired + available, NOERROR
    u16(1),
    u16(2),
    u16(0),
    u16(0),
    dnsName('www.example.com'),
    u16(1),
    u16(1),
    // Answer 1: CNAME
    dnsPointer(12),
    u16(5),
    u16(1),
    u32(3600),
    (() => {
      const rd = dnsName('example-cdn.net');
      return Buffer.concat([u16(rd.length), rd]);
    })(),
    // Answer 2: A record for the CNAME target
    (() => {
      const name = dnsName('example-cdn.net');
      return Buffer.concat([name, u16(1), u16(1), u32(60), u16(4), Buffer.from([93, 184, 216, 34])]);
    })(),
  ]);

  const packets = [
    {
      time: T0,
      data: ethernet(
        ROUTER_MAC,
        CLIENT_MAC,
        0x0800,
        ipv4({ src: CLIENT_IP, dst: DNS_IP, protocol: 17, id: 0x4f2a, ttl: 64, payload: udp({ src: CLIENT_IP, dst: DNS_IP, sport: 54321, dport: 53, payload: query }) }),
      ),
    },
    {
      time: T0 + 0.021884,
      data: ethernet(
        CLIENT_MAC,
        ROUTER_MAC,
        0x0800,
        ipv4({ src: DNS_IP, dst: CLIENT_IP, protocol: 17, id: 0x0001, ttl: 64, df: false, payload: udp({ src: DNS_IP, dst: CLIENT_IP, sport: 53, dport: 54321, payload: answer }) }),
      ),
    },
  ];

  addSample({
    id: 'dns',
    title: 'DNS query and response',
    layers: 'L4/L7',
    blurb:
      'One UDP question and its answer: www.example.com resolves through a CNAME to an A record. The response uses name compression, so the repeated domain costs two bytes instead of seventeen.',
    teaches: [
      'The transaction ID as the only session state a UDP exchange has',
      'Length-prefixed labels — there are no dots on the wire',
      'DNS name compression pointers, visible as 0xC00C in the hex pane',
      'The difference between a DNS TTL (seconds) and an IP TTL (hops)',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* --------------------------------------------------- TCP handshake flow — */
{
  const cPort = 51514;
  const sPort = 80;
  let cSeq = 0x9c3f1a20;
  let sSeq = 0x27ab04d1;
  const packets = [];
  let t = T0;

  const clientOpts = tcpOptions([{ kind: 'mss', value: 1460 }, { kind: 'sackperm' }, { kind: 'ts', value: 3921004 }, { kind: 'nop' }, { kind: 'wscale', value: 7 }]);
  const serverOpts = tcpOptions([{ kind: 'mss', value: 1460 }, { kind: 'sackperm' }, { kind: 'ts', value: 811223, echo: 3921004 }, { kind: 'nop' }, { kind: 'wscale', value: 7 }]);

  const send = (from, opts) => packets.push({ time: t, data: from, ...opts });

  // 1. SYN
  send(
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id: 0x51a1, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq: cSeq, flags: SYN, window: 64240, options: clientOpts }) })),
  );
  // 2. SYN, ACK
  t += 0.014102;
  send(
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: WEB_IP, dst: CLIENT_IP, protocol: 6, id: 0x0000, ttl: 52, payload: tcp({ src: WEB_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq: sSeq, ack: (cSeq + 1) >>> 0, flags: SYN | ACK, window: 65160, options: serverOpts }) })),
  );
  // 3. ACK
  t += 0.000089;
  cSeq = (cSeq + 1) >>> 0;
  sSeq = (sSeq + 1) >>> 0;
  send(
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id: 0x51a2, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq: cSeq, ack: sSeq, flags: ACK, window: 502 }) })),
  );
  // 4. Client data
  const payload = Buffer.from('PING /health HTTP/1.0\r\n\r\n', 'ascii');
  t += 0.000210;
  send(
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id: 0x51a3, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq: cSeq, ack: sSeq, flags: PSH | ACK, window: 502, payload }) })),
  );
  const cSeqAfterData = (cSeq + payload.length) >>> 0;
  // 5. Server ACK of the data
  t += 0.013980;
  send(
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: WEB_IP, dst: CLIENT_IP, protocol: 6, id: 0x0000, ttl: 52, payload: tcp({ src: WEB_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq: sSeq, ack: cSeqAfterData, flags: ACK, window: 509 }) })),
  );
  // 6. Client FIN, ACK
  t += 0.000551;
  send(
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id: 0x51a4, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq: cSeqAfterData, ack: sSeq, flags: FIN | ACK, window: 502 }) })),
  );
  // 7. Server ACK of the FIN
  t += 0.014240;
  send(
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: WEB_IP, dst: CLIENT_IP, protocol: 6, id: 0x0000, ttl: 52, payload: tcp({ src: WEB_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq: sSeq, ack: (cSeqAfterData + 1) >>> 0, flags: ACK, window: 509 }) })),
  );
  // 8. Server FIN, ACK
  t += 0.002104;
  send(
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: WEB_IP, dst: CLIENT_IP, protocol: 6, id: 0x0001, ttl: 52, payload: tcp({ src: WEB_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq: sSeq, ack: (cSeqAfterData + 1) >>> 0, flags: FIN | ACK, window: 509 }) })),
  );
  // 9. Client final ACK
  t += 0.000131;
  send(
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id: 0x51a5, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq: (cSeqAfterData + 1) >>> 0, ack: (sSeq + 1) >>> 0, flags: ACK, window: 502 }) })),
  );

  addSample({
    id: 'tcp',
    title: 'TCP three-way handshake and four-way teardown',
    layers: 'L4',
    blurb:
      'A complete connection life cycle: SYN, SYN+ACK, ACK, one data segment, then the four-message close. Sequence numbers start random and advance by exactly the number of bytes sent.',
    teaches: [
      'Why SYN and FIN each consume one sequence number even though they carry no data',
      'MSS, window scale, SACK and timestamps negotiated in the handshake — and only there',
      'Each direction closing independently, which is why teardown takes four messages',
      'Reading the round-trip time from the SYN to SYN+ACK gap',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* ----------------------------------------------------------------- HTTP — */
{
  const cPort = 49812;
  const sPort = 80;
  let cSeq = 0x0c41d900;
  let sSeq = 0x77b21e40;
  const packets = [];
  let t = T0;

  const push = (data) => packets.push({ time: t, data });
  const clientOpts = tcpOptions([{ kind: 'mss', value: 1460 }, { kind: 'sackperm' }, { kind: 'nop' }, { kind: 'wscale', value: 7 }]);
  const serverOpts = tcpOptions([{ kind: 'mss', value: 1460 }, { kind: 'sackperm' }, { kind: 'nop' }, { kind: 'wscale', value: 7 }]);

  const toServer = (seq, ack, flags, payload = Buffer.alloc(0), id = 0x2200, options = Buffer.alloc(0)) =>
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: WEB_IP, protocol: 6, id, payload: tcp({ src: CLIENT_IP, dst: WEB_IP, sport: cPort, dport: sPort, seq, ack, flags, window: 64240, payload, options }) }));
  const toClient = (seq, ack, flags, payload = Buffer.alloc(0), id = 0x8800, options = Buffer.alloc(0)) =>
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: WEB_IP, dst: CLIENT_IP, protocol: 6, id, ttl: 54, payload: tcp({ src: WEB_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq, ack, flags, window: 65160, payload, options }) }));

  push(toServer(cSeq, 0, SYN, Buffer.alloc(0), 0x2201, clientOpts));
  t += 0.018440;
  push(toClient(sSeq, (cSeq + 1) >>> 0, SYN | ACK, Buffer.alloc(0), 0x8801, serverOpts));
  t += 0.000094;
  cSeq = (cSeq + 1) >>> 0;
  sSeq = (sSeq + 1) >>> 0;
  push(toServer(cSeq, sSeq, ACK, Buffer.alloc(0), 0x2202));

  const request = Buffer.from(
    [
      'GET /osi-lab/index.html?lesson=encapsulation HTTP/1.1',
      'Host: www.example.com',
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64) NetworkingLab/1.0',
      'Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
      'Accept-Language: en-GB,en;q=0.9',
      'Accept-Encoding: gzip, deflate',
      'Cookie: session=7f3a9c21b48e5d06; theme=dark',
      'Connection: keep-alive',
      '',
      '',
    ].join('\r\n'),
    'ascii',
  );
  t += 0.000178;
  push(toServer(cSeq, sSeq, PSH | ACK, request, 0x2203));
  const cSeq2 = (cSeq + request.length) >>> 0;

  t += 0.018002;
  push(toClient(sSeq, cSeq2, ACK, Buffer.alloc(0), 0x8802));

  const body = Buffer.from(
    [
      '<!doctype html>',
      '<html lang="en">',
      '  <head><meta charset="utf-8"><title>OSI Lab</title></head>',
      '  <body>',
      '    <h1>Encapsulation</h1>',
      '    <p>This body is Layer 7. Everything wrapped around it is delivery.</p>',
      '  </body>',
      '</html>',
      '',
    ].join('\n'),
    'utf8',
  );
  const response = Buffer.concat([
    Buffer.from(
      [
        'HTTP/1.1 200 OK',
        'Date: Thu, 14 Mar 2024 09:15:00 GMT',
        'Server: nginx/1.24.0',
        'Content-Type: text/html; charset=utf-8',
        `Content-Length: ${body.length}`,
        'Cache-Control: max-age=300',
        'Set-Cookie: session=7f3a9c21b48e5d06; Path=/; HttpOnly',
        'Connection: keep-alive',
        '',
        '',
      ].join('\r\n'),
      'ascii',
    ),
    body,
  ]);
  t += 0.002210;
  push(toClient(sSeq, cSeq2, PSH | ACK, response, 0x8803));
  const sSeq2 = (sSeq + response.length) >>> 0;

  t += 0.000122;
  push(toServer(cSeq2, sSeq2, ACK, Buffer.alloc(0), 0x2204));

  // Second request: a gzip + chunked response, so Layer 6 has something to show.
  const request2 = Buffer.from(
    [
      'GET /osi-lab/style.css HTTP/1.1',
      'Host: www.example.com',
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64) NetworkingLab/1.0',
      'Accept: text/css,*/*;q=0.1',
      'Accept-Encoding: gzip, deflate',
      'Referer: http://www.example.com/osi-lab/index.html',
      'Cookie: session=7f3a9c21b48e5d06; theme=dark',
      'Connection: keep-alive',
      '',
      '',
    ].join('\r\n'),
    'ascii',
  );
  t += 0.004401;
  push(toServer(cSeq2, sSeq2, PSH | ACK, request2, 0x2205));
  const cSeq3 = (cSeq2 + request2.length) >>> 0;

  const css = Buffer.from(
    'body{font-family:system-ui,sans-serif;background:#0b1020;color:#e6edf7;margin:0}\n' +
      'h1{font-weight:600;letter-spacing:-0.01em}\n' +
      '.layer{border-left:4px solid currentColor;padding-left:12px}\n',
    'utf8',
  );
  const gz = gzipSync(css);
  const chunked = Buffer.concat([
    Buffer.from(`${gz.length.toString(16)}\r\n`, 'ascii'),
    gz,
    Buffer.from('\r\n0\r\n\r\n', 'ascii'),
  ]);
  const response2 = Buffer.concat([
    Buffer.from(
      [
        'HTTP/1.1 200 OK',
        'Date: Thu, 14 Mar 2024 09:15:00 GMT',
        'Server: nginx/1.24.0',
        'Content-Type: text/css; charset=utf-8',
        'Content-Encoding: gzip',
        'Transfer-Encoding: chunked',
        'Vary: Accept-Encoding',
        'Connection: keep-alive',
        '',
        '',
      ].join('\r\n'),
      'ascii',
    ),
    chunked,
  ]);
  t += 0.019930;
  push(toClient(sSeq2, cSeq3, PSH | ACK, response2, 0x8804));
  const sSeq3 = (sSeq2 + response2.length) >>> 0;

  t += 0.000118;
  push(toServer(cSeq3, sSeq3, ACK, Buffer.alloc(0), 0x2206));
  t += 0.301004;
  push(toServer(cSeq3, sSeq3, FIN | ACK, Buffer.alloc(0), 0x2207));
  t += 0.018221;
  push(toClient(sSeq3, (cSeq3 + 1) >>> 0, FIN | ACK, Buffer.alloc(0), 0x8805));
  t += 0.000101;
  push(toServer((cSeq3 + 1) >>> 0, (sSeq3 + 1) >>> 0, ACK, Buffer.alloc(0), 0x2208));

  addSample({
    id: 'http',
    title: 'HTTP GET request and response (unencrypted)',
    layers: 'L5/L6/L7',
    blurb:
      'Two plaintext HTTP exchanges over one persistent connection. The first response is readable HTML; the second is gzip-compressed and chunked, which puts real content on Layer 6.',
    teaches: [
      'One byte range carrying Layers 5, 6 and 7 at once: Cookie, Content-Type, and the request line',
      'Why Content-Encoding: gzip is a presentation-layer concern, not an application one',
      'Chunked transfer encoding as message framing over a stream that has none',
      'Everything — URL, cookie, headers — readable in the ASCII column, because there is no TLS',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* ------------------------------------------------------------------ TLS — */
{
  const cPort = 52310;
  const sPort = 443;
  let cSeq = 0xa1b20000;
  let sSeq = 0x5f0c1200;
  const packets = [];
  let t = T0;
  const TLS_IP = '104.18.32.47';

  const toServer = (seq, ack, flags, payload = Buffer.alloc(0), id = 0x3100, options = Buffer.alloc(0)) =>
    ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4({ src: CLIENT_IP, dst: TLS_IP, protocol: 6, id, payload: tcp({ src: CLIENT_IP, dst: TLS_IP, sport: cPort, dport: sPort, seq, ack, flags, window: 64240, payload, options }) }));
  const toClient = (seq, ack, flags, payload = Buffer.alloc(0), id = 0x9100, options = Buffer.alloc(0)) =>
    ethernet(CLIENT_MAC, ROUTER_MAC, 0x0800, ipv4({ src: TLS_IP, dst: CLIENT_IP, protocol: 6, id, ttl: 57, payload: tcp({ src: TLS_IP, dst: CLIENT_IP, sport: sPort, dport: cPort, seq, ack, flags, window: 65535, payload, options }) }));

  const opts = tcpOptions([{ kind: 'mss', value: 1460 }, { kind: 'sackperm' }, { kind: 'nop' }, { kind: 'wscale', value: 8 }]);

  packets.push({ time: t, data: toServer(cSeq, 0, SYN, Buffer.alloc(0), 0x3101, opts) });
  t += 0.011821;
  packets.push({ time: t, data: toClient(sSeq, (cSeq + 1) >>> 0, SYN | ACK, Buffer.alloc(0), 0x9101, opts) });
  t += 0.000088;
  cSeq = (cSeq + 1) >>> 0;
  sSeq = (sSeq + 1) >>> 0;
  packets.push({ time: t, data: toServer(cSeq, sSeq, ACK, Buffer.alloc(0), 0x3102) });

  /* --- ClientHello ------------------------------------------------------ */
  const clientRandom = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff));
  const legacySessionId = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 91 + 200) & 0xff));
  const cipherSuites = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];

  const host = 'secure.example.com';
  const sniData = Buffer.concat([u16(host.length + 3), u8(0), u16(host.length), Buffer.from(host, 'ascii')]);
  const alpnProtos = ['h2', 'http/1.1'];
  const alpnList = Buffer.concat(alpnProtos.map((p) => Buffer.concat([u8(p.length), Buffer.from(p, 'ascii')])));
  const alpnData = Buffer.concat([u16(alpnList.length), alpnList]);
  const groups = [0x001d, 0x0017, 0x0018, 0x0019];
  const groupsData = Buffer.concat([u16(groups.length * 2), ...groups.map(u16)]);
  const sigAlgs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];
  const sigAlgsData = Buffer.concat([u16(sigAlgs.length * 2), ...sigAlgs.map(u16)]);
  const versionsData = Buffer.concat([u8(4), u16(0x0304), u16(0x0303)]);
  const keyShareEntry = Buffer.concat([u16(0x001d), u16(32), Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 53 + 7) & 0xff))]);
  const keyShareData = Buffer.concat([u16(keyShareEntry.length), keyShareEntry]);

  const ext = (type, data) => Buffer.concat([u16(type), u16(data.length), data]);
  const extensions = Buffer.concat([
    ext(0x0000, sniData),
    ext(0x0017, Buffer.alloc(0)), // extended_master_secret
    ext(0x000d, sigAlgsData),
    ext(0x0010, alpnData),
    ext(0x000a, groupsData),
    ext(0x000b, Buffer.concat([u8(1), u8(0)])), // ec_point_formats: uncompressed
    ext(0x0023, Buffer.alloc(0)), // session_ticket, empty
    ext(0x002b, versionsData),
    ext(0x0033, keyShareData),
    ext(0x002d, Buffer.concat([u8(1), u8(1)])), // psk_key_exchange_modes
    ext(0xff01, Buffer.concat([u8(0)])), // renegotiation_info
  ]);

  const chBody = Buffer.concat([
    u16(0x0303),
    clientRandom,
    u8(legacySessionId.length),
    legacySessionId,
    u16(cipherSuites.length * 2),
    ...cipherSuites.map(u16),
    u8(1),
    u8(0),
    u16(extensions.length),
    extensions,
  ]);
  const clientHello = Buffer.concat([u8(1), u24(chBody.length), chBody]);
  const chRecord = Buffer.concat([u8(22), u16(0x0301), u16(clientHello.length), clientHello]);

  t += 0.000221;
  packets.push({ time: t, data: toServer(cSeq, sSeq, PSH | ACK, chRecord, 0x3103) });
  const cSeq2 = (cSeq + chRecord.length) >>> 0;

  t += 0.011994;
  packets.push({ time: t, data: toClient(sSeq, cSeq2, ACK, Buffer.alloc(0), 0x9102) });

  /* --- ServerHello + Change Cipher Spec + encrypted handshake ----------- */
  const serverRandom = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 17 + 129) & 0xff));
  const shExtensions = Buffer.concat([
    ext(0x002b, u16(0x0304)),
    ext(0x0033, Buffer.concat([u16(0x001d), u16(32), Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 71 + 23) & 0xff))])),
  ]);
  const shBody = Buffer.concat([
    u16(0x0303),
    serverRandom,
    u8(legacySessionId.length),
    legacySessionId,
    u16(0x1301),
    u8(0),
    u16(shExtensions.length),
    shExtensions,
  ]);
  const serverHello = Buffer.concat([u8(2), u24(shBody.length), shBody]);
  const shRecord = Buffer.concat([u8(22), u16(0x0303), u16(serverHello.length), serverHello]);
  const ccsRecord = Buffer.concat([u8(20), u16(0x0303), u16(1), u8(1)]);
  const encHandshake = Buffer.from(Array.from({ length: 512 }, (_, i) => (i * 149 + 61) & 0xff));
  const encRecord = Buffer.concat([u8(23), u16(0x0303), u16(encHandshake.length), encHandshake]);

  t += 0.001402;
  packets.push({ time: t, data: toClient(sSeq, cSeq2, PSH | ACK, Buffer.concat([shRecord, ccsRecord, encRecord]), 0x9103) });
  const sSeq2 = (sSeq + shRecord.length + ccsRecord.length + encRecord.length) >>> 0;

  t += 0.000109;
  packets.push({ time: t, data: toServer(cSeq2, sSeq2, ACK, Buffer.alloc(0), 0x3104) });

  const clientCcs = Buffer.concat([u8(20), u16(0x0303), u16(1), u8(1)]);
  const clientFinished = Buffer.from(Array.from({ length: 52 }, (_, i) => (i * 211 + 97) & 0xff));
  const clientFinRecord = Buffer.concat([u8(23), u16(0x0303), u16(clientFinished.length), clientFinished]);
  t += 0.000402;
  packets.push({ time: t, data: toServer(cSeq2, sSeq2, PSH | ACK, Buffer.concat([clientCcs, clientFinRecord]), 0x3105) });
  const cSeq3 = (cSeq2 + clientCcs.length + clientFinRecord.length) >>> 0;

  const appData = Buffer.from(Array.from({ length: 320 }, (_, i) => (i * 83 + 199) & 0xff));
  const appRecord = Buffer.concat([u8(23), u16(0x0303), u16(appData.length), appData]);
  t += 0.000308;
  packets.push({ time: t, data: toServer(cSeq3, sSeq2, PSH | ACK, appRecord, 0x3106) });

  addSample({
    id: 'tls',
    title: 'TLS 1.3 handshake (ClientHello and ServerHello)',
    layers: 'L5/L6',
    blurb:
      'A full TLS handshake over TCP 443. The ClientHello carries SNI, ALPN, cipher suites and a key share in clear text; after the ServerHello everything turns into opaque Application Data.',
    teaches: [
      'TLS doing real session-layer work: session IDs, tickets, and resumption across connections',
      'Layer 6 in action — cipher and compression negotiation decides how everything above is represented',
      'Why the record layer says "TLS 1.0" and the supported_versions extension says 1.3',
      'SNI leaking the destination hostname even though the session is encrypted',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* ----------------------------------------------------------------- DHCP — */
{
  const xid = 0x3d1e8a55;
  const clientMacBuf = Buffer.from(CLIENT_MAC.split(':').map((h) => parseInt(h, 16)));

  const bootp = ({ op, ciaddr, yiaddr, siaddr, options, broadcast }) =>
    Buffer.concat([
      u8(op),
      u8(1),
      u8(6),
      u8(0),
      u32(xid),
      u16(0),
      u16(broadcast ? 0x8000 : 0),
      Buffer.from(ciaddr.split('.').map(Number)),
      Buffer.from(yiaddr.split('.').map(Number)),
      Buffer.from(siaddr.split('.').map(Number)),
      Buffer.alloc(4),
      clientMacBuf,
      Buffer.alloc(10),
      Buffer.alloc(64), // sname
      Buffer.alloc(128), // file
      u32(0x63825363),
      options,
    ]);

  const opt = (code, data) => Buffer.concat([u8(code), u8(data.length), data]);
  const END = Buffer.from([0xff]);

  const discoverOpts = Buffer.concat([
    opt(53, Buffer.from([1])),
    opt(61, Buffer.concat([u8(1), clientMacBuf])),
    opt(12, Buffer.from('lab-workstation', 'ascii')),
    opt(60, Buffer.from('MSFT 5.0', 'ascii')),
    opt(55, Buffer.from([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])),
    END,
  ]);
  const offerOpts = Buffer.concat([
    opt(53, Buffer.from([2])),
    opt(54, Buffer.from([192, 168, 1, 1])),
    opt(51, u32(86400)),
    opt(58, u32(43200)),
    opt(59, u32(75600)),
    opt(1, Buffer.from([255, 255, 255, 0])),
    opt(3, Buffer.from([192, 168, 1, 1])),
    opt(6, Buffer.from([192, 168, 1, 1, 1, 1, 1, 1])),
    opt(15, Buffer.from('lab.internal', 'ascii')),
    END,
  ]);
  const requestOpts = Buffer.concat([
    opt(53, Buffer.from([3])),
    opt(61, Buffer.concat([u8(1), clientMacBuf])),
    opt(50, Buffer.from([192, 168, 1, 42])),
    opt(54, Buffer.from([192, 168, 1, 1])),
    opt(12, Buffer.from('lab-workstation', 'ascii')),
    opt(55, Buffer.from([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])),
    END,
  ]);
  const ackOpts = Buffer.concat([
    opt(53, Buffer.from([5])),
    opt(54, Buffer.from([192, 168, 1, 1])),
    opt(51, u32(86400)),
    opt(58, u32(43200)),
    opt(59, u32(75600)),
    opt(1, Buffer.from([255, 255, 255, 0])),
    opt(3, Buffer.from([192, 168, 1, 1])),
    opt(6, Buffer.from([192, 168, 1, 1, 1, 1, 1, 1])),
    opt(15, Buffer.from('lab.internal', 'ascii')),
    END,
  ]);

  const broadcastFrame = (payload, srcIp, dstIp, srcMacAddr, dstMacAddr, sport, dport) =>
    ethernet(dstMacAddr, srcMacAddr, 0x0800, ipv4({ src: srcIp, dst: dstIp, protocol: 17, id: 0, ttl: srcIp === '0.0.0.0' ? 128 : 64, df: false, payload: udp({ src: srcIp, dst: dstIp, sport, dport, payload }) }));

  const packets = [
    {
      time: T0,
      data: broadcastFrame(bootp({ op: 1, ciaddr: '0.0.0.0', yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: discoverOpts, broadcast: true }), '0.0.0.0', '255.255.255.255', CLIENT_MAC, 'ff:ff:ff:ff:ff:ff', 68, 67),
    },
    {
      time: T0 + 0.004102,
      data: broadcastFrame(bootp({ op: 2, ciaddr: '0.0.0.0', yiaddr: '192.168.1.42', siaddr: '192.168.1.1', options: offerOpts, broadcast: true }), '192.168.1.1', '255.255.255.255', ROUTER_MAC, 'ff:ff:ff:ff:ff:ff', 67, 68),
    },
    {
      time: T0 + 0.004881,
      data: broadcastFrame(bootp({ op: 1, ciaddr: '0.0.0.0', yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: requestOpts, broadcast: true }), '0.0.0.0', '255.255.255.255', CLIENT_MAC, 'ff:ff:ff:ff:ff:ff', 68, 67),
    },
    {
      time: T0 + 0.008440,
      data: broadcastFrame(bootp({ op: 2, ciaddr: '0.0.0.0', yiaddr: '192.168.1.42', siaddr: '192.168.1.1', options: ackOpts, broadcast: true }), '192.168.1.1', '255.255.255.255', ROUTER_MAC, 'ff:ff:ff:ff:ff:ff', 67, 68),
    },
  ];

  addSample({
    id: 'dhcp',
    title: 'DHCP lease (DORA exchange)',
    layers: 'L2/L4/L7',
    blurb:
      'Discover, Offer, Request, Acknowledge. Watch a host with no address at all bootstrap itself, using broadcast at Layer 2 and Layer 3 because it has nothing else to work with.',
    teaches: [
      'Why the first packet has source 0.0.0.0 and destination 255.255.255.255',
      'A transaction ID acting as the session, because UDP provides none',
      'DHCP options as type-length-value structures, including the vendor fingerprint',
      'That the same MAC drives the lease — which is why MAC randomisation changes your IP',
    ],
    format: 'pcap',
    data: writePcap(packets),
  });
}

/* ---------------------------------------------------- IPv6 + VLAN + DNS — */
{
  const V6_CLIENT = '2001:db8:1234:5678::a1';
  const V6_DNS = '2001:4860:4860::8888';
  const V6_ROUTER_MAC = ROUTER_MAC;

  const query = Buffer.concat([
    u16(0x2b7c),
    u16(0x0120),
    u16(1),
    u16(0),
    u16(0),
    u16(1),
    dnsName('ipv6.example.org'),
    u16(28), // AAAA
    u16(1),
    // EDNS0 OPT pseudo-record in the additional section
    Buffer.from([0x00]),
    u16(41),
    u16(1232),
    u32(0),
    u16(0),
  ]);

  const answer = Buffer.concat([
    u16(0x2b7c),
    u16(0x8180),
    u16(1),
    u16(1),
    u16(0),
    u16(0),
    dnsName('ipv6.example.org'),
    u16(28),
    u16(1),
    dnsPointer(12),
    u16(28),
    u16(1),
    u32(300),
    u16(16),
    Buffer.from('20010db8123456780000000000000f0d', 'hex'),
  ]);

  const pingData = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x30 + (i % 16)));

  const packets = [
    {
      time: T0,
      data: ethernet(V6_ROUTER_MAC, CLIENT_MAC, 0x86dd, ipv6({ src: V6_CLIENT, dst: V6_DNS, nextHeader: 17, hopLimit: 64, payload: udp({ src: V6_CLIENT, dst: V6_DNS, sport: 57422, dport: 53, payload: query, v6: true }) }), 20),
    },
    {
      time: T0 + 0.024119,
      data: ethernet(CLIENT_MAC, V6_ROUTER_MAC, 0x86dd, ipv6({ src: V6_DNS, dst: V6_CLIENT, nextHeader: 17, hopLimit: 57, payload: udp({ src: V6_DNS, dst: V6_CLIENT, sport: 53, dport: 57422, payload: answer, v6: true }) }), 20),
    },
    {
      time: T0 + 0.024902,
      data: ethernet(V6_ROUTER_MAC, CLIENT_MAC, 0x86dd, ipv6({ src: V6_CLIENT, dst: '2001:db8:1234:5678::f0d', nextHeader: 58, hopLimit: 64, payload: icmp6Echo({ type: 128, id: 0x1b2c, seq: 1, data: pingData, src: V6_CLIENT, dst: '2001:db8:1234:5678::f0d' }) }), 20),
    },
    {
      time: T0 + 0.026551,
      data: ethernet(CLIENT_MAC, V6_ROUTER_MAC, 0x86dd, ipv6({ src: '2001:db8:1234:5678::f0d', dst: V6_CLIENT, nextHeader: 58, hopLimit: 64, payload: icmp6Echo({ type: 129, id: 0x1b2c, seq: 1, data: pingData, src: '2001:db8:1234:5678::f0d', dst: V6_CLIENT }) }), 20),
    },
  ];

  addSample({
    id: 'ipv6',
    title: 'IPv6 over a VLAN trunk, with DNS and ping6',
    layers: 'L2/L3',
    blurb:
      'The same conversations you already know, one layer down: 802.1Q VLAN tags at Layer 2, 128-bit addresses at Layer 3, an AAAA lookup, and an ICMPv6 echo.',
    teaches: [
      'The 4-byte 802.1Q tag sitting between the source MAC and the EtherType',
      'How the IPv6 header differs: fixed 40 bytes, no checksum, no fragmentation by routers',
      'Payload Length counting only what follows the header, unlike IPv4 Total Length',
      'ICMPv6 checksums covering a pseudo-header, which plain ICMP does not',
    ],
    format: 'pcap',
    data: writePcap(packets, { endian: 'big' }),
  });
}

/* ------------------------------------------ Wi-Fi (radiotap + 802.11) -- */
{
  const AP_MAC = 'fc:ec:da:44:55:66';
  const STA_MAC = '3c:07:54:1a:2b:3c';
  const BSSID = AP_MAC;
  const CH_FREQ = 2437; // channel 6
  const CHAN_FLAGS_CCK = 0x00a0; // 2 GHz + CCK
  const CHAN_FLAGS_OFDM = 0x00c0; // 2 GHz + OFDM
  const RSN = [
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
    0x00, 0x00,
  ];
  const RATES = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
  const packets = [];
  let t = T0;
  let tsf = 728113940;
  let seq = 2101;

  const beaconBody = (timestamp) =>
    Buffer.concat([
      beaconFixed({ timestamp, interval: 100, capabilities: 0x0431 }),
      dot11Tag(0, 'OSI-Lab'),
      dot11Tag(1, RATES),
      dot11Tag(3, [6]),
      dot11Tag(48, RSN),
    ]);

  packets.push({
    time: t,
    direction: 1,
    receptionType: 3,
    comment: 'Beacon: the access point announcing the cell about ten times a second.',
    data: Buffer.concat([
      radiotap({ tsft: tsf, flags: 0x00, rate: 1, freq: CH_FREQ, chanFlags: CHAN_FLAGS_CCK, signal: -38, noise: -95, antenna: 0 }),
      dot11({ type: DOT11.MGMT, subtype: 8, addresses: ['ff:ff:ff:ff:ff:ff', AP_MAC, BSSID], sequence: seq++ }),
      beaconBody(tsf),
    ]),
  });

  t += 0.041882;
  tsf += 41882;
  packets.push({
    time: t,
    direction: 1,
    receptionType: 3,
    data: Buffer.concat([
      radiotap({ tsft: tsf, flags: 0x00, rate: 1, freq: CH_FREQ, chanFlags: CHAN_FLAGS_CCK, signal: -57, noise: -95, antenna: 0 }),
      dot11({ type: DOT11.MGMT, subtype: 4, addresses: ['ff:ff:ff:ff:ff:ff', STA_MAC, 'ff:ff:ff:ff:ff:ff'], sequence: seq++ }),
      Buffer.concat([dot11Tag(0, ''), dot11Tag(1, RATES)]),
    ]),
  });

  t += 0.000512;
  tsf += 512;
  packets.push({
    time: t,
    direction: 1,
    receptionType: 1,
    data: Buffer.concat([
      radiotap({ tsft: tsf, flags: 0x00, rate: 1, freq: CH_FREQ, chanFlags: CHAN_FLAGS_CCK, signal: -39, noise: -95, antenna: 0 }),
      dot11({ type: DOT11.MGMT, subtype: 5, addresses: [STA_MAC, AP_MAC, BSSID], sequence: seq++ }),
      beaconBody(tsf),
    ]),
  });

  const dnsQuery = Buffer.concat([
    u16(0x51ad), u16(0x0100), u16(1), u16(0), u16(0), u16(0),
    dnsName('lab.example.net'), u16(1), u16(1),
  ]);
  const queryPayload = Buffer.concat([
    llcSnap(0x0800),
    ipv4({
      src: CLIENT_IP,
      dst: DNS_IP,
      protocol: 17,
      id: 0x7c11,
      ttl: 64,
      payload: udp({ src: CLIENT_IP, dst: DNS_IP, sport: 51224, dport: 53, payload: dnsQuery }),
    }),
  ]);

  t += 0.118440;
  packets.push({
    time: t,
    direction: 2,
    receptionType: 1,
    comment: 'The only 802.11 frame type that carries anything above Layer 2.',
    data: Buffer.concat([
      radiotap({
        flags: 0x00,
        freq: CH_FREQ,
        chanFlags: CHAN_FLAGS_OFDM,
        signal: -55,
        noise: -95,
        antenna: 1,
        mcs: { known: 0x07, flags: 0x05, index: 7 },
      }),
      dot11({
        type: DOT11.DATA,
        subtype: 8,
        flags: DOT11.TO_DS,
        duration: 44,
        addresses: [BSSID, STA_MAC, AP_MAC],
        sequence: seq,
        qos: 0x0000,
      }),
      queryPayload,
    ]),
  });

  t += 0.000016;
  packets.push({
    time: t,
    direction: 1,
    receptionType: 1,
    comment: 'Layer 2 reliability: every unicast Wi-Fi frame is acknowledged within microseconds.',
    data: Buffer.concat([
      radiotap({ flags: 0x00, rate: 24, freq: CH_FREQ, chanFlags: CHAN_FLAGS_OFDM, signal: -38, noise: -95, antenna: 0 }),
      dot11({ type: DOT11.CONTROL, subtype: 13, addresses: [STA_MAC] }),
    ]),
  });

  t += 0.003104;
  packets.push({
    time: t,
    direction: 1,
    receptionType: 4,
    comment: 'Hardware flagged a bad FCS: monitor mode hears frames it cannot decode cleanly.',
    data: Buffer.concat([
      radiotap({
        flags: 0x40,
        freq: CH_FREQ,
        chanFlags: CHAN_FLAGS_OFDM,
        signal: -84,
        noise: -95,
        antenna: 1,
        mcs: { known: 0x07, flags: 0x00, index: 0 },
      }),
      dot11({
        type: DOT11.DATA,
        subtype: 8,
        flags: DOT11.TO_DS | DOT11.RETRY,
        duration: 44,
        addresses: [BSSID, STA_MAC, AP_MAC],
        sequence: seq,
        qos: 0x0000,
      }),
      queryPayload,
    ]),
  });
  seq++;

  const dnsAnswer = Buffer.concat([
    u16(0x51ad), u16(0x8180), u16(1), u16(1), u16(0), u16(0),
    dnsName('lab.example.net'), u16(1), u16(1),
    dnsPointer(12), u16(1), u16(1), u32(120), u16(4),
    Buffer.from([192, 168, 1, 80]),
  ]);

  t += 0.021004;
  packets.push({
    time: t,
    direction: 1,
    receptionType: 1,
    data: Buffer.concat([
      radiotap({
        flags: 0x00,
        freq: CH_FREQ,
        chanFlags: CHAN_FLAGS_OFDM,
        signal: -38,
        noise: -95,
        antenna: 0,
        mcs: { known: 0x07, flags: 0x05, index: 15 },
      }),
      dot11({
        type: DOT11.DATA,
        subtype: 8,
        flags: DOT11.FROM_DS,
        duration: 44,
        addresses: [STA_MAC, BSSID, AP_MAC],
        sequence: seq++,
        qos: 0x0000,
      }),
      Buffer.concat([
        llcSnap(0x0800),
        ipv4({
          src: DNS_IP,
          dst: CLIENT_IP,
          protocol: 17,
          id: 0x0002,
          ttl: 64,
          df: false,
          payload: udp({ src: DNS_IP, dst: CLIENT_IP, sport: 53, dport: 51224, payload: dnsAnswer }),
        }),
      ]),
    ]),
  });

  addSample({
    id: 'wifi',
    title: 'Wi-Fi monitor mode: real Layer 1 measurements',
    layers: 'L1/L2',
    blurb:
      'The one capture type that carries genuine physical-layer data. A radiotap header records what the radio actually measured — channel frequency, signal strength in dBm, antenna, modulation and coding — as real bytes you can highlight in the hex pane.',
    teaches: [
      'Layer 1 with measured values: 2437 MHz, -38 dBm, MCS 7, 400 ns guard interval',
      'An 802.11 header with up to four address fields whose meaning depends on two flag bits',
      'Beacons, probe requests and acknowledgements: frames that exist only to manage a shared medium',
      'A retry with a bad FCS at -84 dBm, which is what a struggling client looks like before TCP notices',
      'pcapng per-packet metadata: direction, reception type and packet comments',
    ],
    format: 'pcapng',
    data: writePcapng(packets, {
      linkType: 127,
      ifName: 'wlan0mon',
      ifDescription: 'Atheros AR9280 in monitor mode, channel 6',
      ifHardware: 'Qualcomm Atheros AR9280 802.11a/b/g/n',
      ifOs: 'Linux 6.8.0 (ath9k)',
      ifSpeed: 300000000,
      ifFcsLen: 0,
      ifTsResol: 9,
      comment: 'PCAP-to-OSI sample: Wi-Fi monitor mode with radiotap physical-layer metadata',
    }),
  });
}

/* --------------------------------------------------------------- output — */

const order = ['arp', 'tcp', 'dns', 'http', 'tls', 'icmp', 'dhcp', 'ipv6', 'wifi'];
samples.sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));

const entries = samples.map((s) => {
  const base64 = s.data.toString('base64');
  return `  {
    id: '${s.id}',
    title: ${JSON.stringify(s.title)},
    layers: ${JSON.stringify(s.layers)},
    fileName: '${s.id}-sample.${s.format}',
    format: '${s.format}',
    byteLength: ${s.data.length},
    blurb: ${JSON.stringify(s.blurb)},
    teaches: ${JSON.stringify(s.teaches, null, 6).replace(/\n/g, '\n    ')},
    base64:
      '${base64.match(/.{1,96}/g).join("' +\n      '")}',
  },`;
});

const out = `/**
 * Bundled teaching captures.
 *
 * GENERATED FILE — do not edit by hand. Run \`npm run samples\` to rebuild it
 * from tools/gen-samples.mjs.
 *
 * Every capture here is synthetic: the frames were constructed byte by byte
 * from the relevant RFCs, with real Internet checksums and real TCP sequence
 * arithmetic, so they behave identically in this tool, in Wireshark and in
 * tshark. Nothing was recorded from a real network, so there is no traffic
 * from real people in the classroom material.
 */

export interface SampleCapture {
  id: string;
  title: string;
  /** Which OSI layers this capture is the best illustration of. */
  layers: string;
  fileName: string;
  format: 'pcap' | 'pcapng';
  byteLength: number;
  blurb: string;
  teaches: string[];
  base64: string;
}

export const SAMPLE_CAPTURES: SampleCapture[] = [
${entries.join('\n')}
];

/** Decode a bundled sample into an ArrayBuffer, exactly as if it were dropped in. */
export function decodeSample(sample: SampleCapture): ArrayBuffer {
  const binary = atob(sample.base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
}
`;

writeFileSync(new URL('../src/data/samples.ts', import.meta.url), out);
console.log(`Wrote ${samples.length} samples (${samples.map((s) => `${s.id}:${s.data.length}B`).join(', ')})`);
