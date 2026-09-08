/**
 * Bundled teaching captures.
 *
 * GENERATED FILE — do not edit by hand. Run `npm run samples` to rebuild it
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
  {
    id: 'arp',
    title: "ARP address resolution",
    layers: "L2",
    fileName: 'arp-sample.pcap',
    format: 'pcap',
    byteLength: 252,
    blurb: "A host needs the MAC address behind 192.168.1.1, broadcasts the question, and gets a unicast answer. The third frame is a gratuitous ARP — the router announcing itself unprompted.",
    teaches: [
          "ARP carries IP addresses but is not carried inside IP — it stops dead at Layer 2",
          "Why the request goes to ff:ff:ff:ff:ff:ff and the reply does not",
          "Ethernet padding: a 28-byte message inside a 60-byte frame"
    ],
    base64:
      '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAFMDyZQAAAAA8AAAAPAAAAP///////zwHVBorPAgGAAEIAAYEAAE8B1QaKzzAqAEq' +
      'AAAAAAAAwKgBAQAAAAAAAAAAAAAAAAAAAAAAABTA8mWcAQAAPAAAADwAAAA8B1QaKzz87NpEVWYIBgABCAAGBAAC/OzaRFVm' +
      'wKgBATwHVBorPMCoASoAAAAAAAAAAAAAAAAAAAAAAAAVwPJl4BwDADwAAAA8AAAA/////////OzaRFVmCAYAAQgABgQAAfzs' +
      '2kRVZsCoAQEAAAAAAADAqAEBAAAAAAAAAAAAAAAAAAAAAAAA',
  },
  {
    id: 'tcp',
    title: "TCP three-way handshake and four-way teardown",
    layers: "L4",
    fileName: 'tcp-sample.pcap',
    format: 'pcap',
    byteLength: 755,
    blurb: "A complete connection life cycle: SYN, SYN+ACK, ACK, one data segment, then the four-message close. Sequence numbers start random and advance by exactly the number of bytes sent.",
    teaches: [
          "Why SYN and FIN each consume one sequence number even though they carry no data",
          "MSS, window scale, SACK and timestamps negotiated in the handshake — and only there",
          "Each direction closing independently, which is why teardown takes four messages",
          "Reading the round-trip time from the SYN to SYN+ACK gap"
    ],
    base64:
      '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAFMDyZQAAAABKAAAASgAAAPzs2kRVZjwHVBorPAgARQAAPFGhQABABvFtwKgBKl24' +
      '2CLJOgBQnD8aIAAAAACgAvrwANAAAAIEBbQEAggKADvUbAAAAAABAwMHFMDyZRY3AABKAAAASgAAADwHVBorPPzs2kRVZggA' +
      'RQAAPAAAQAA0Bk8PXbjYIsCoASoAUMk6J6sE0Zw/GiGgEv6Ib8cAAAIEBbQEAggKAAxg1wA71GwBAwMHFMDyZW83AAA8AAAA' +
      'PAAAAPzs2kRVZjwHVBorPAgARQAAKFGiQABABvGAwKgBKl242CLJOgBQnD8aISerBNJQEAH2CckAAAAAAAAAABTA8mVBOAAA' +
      'TwAAAE8AAAD87NpEVWY8B1QaKzwIAEUAAEFRo0AAQAbxZsCoASpduNgiyToAUJw/GiEnqwTSUBgB9tKZAABQSU5HIC9oZWFs' +
      'dGggSFRUUC8xLjANCg0KFMDyZd1uAAA8AAAAPAAAADwHVBorPPzs2kRVZggARQAAKAAAQAA0Bk8jXbjYIsCoASoAUMk6J6sE' +
      '0pw/GjpQEAH9CakAAAAAAAAAABTA8mUEcQAAPAAAADwAAAD87NpEVWY8B1QaKzwIAEUAAChRpEAAQAbxfsCoASpduNgiyToA' +
      'UJw/GjonqwTSUBEB9gmvAAAAAAAAAAAUwPJlpKgAADwAAAA8AAAAPAdUGis8/OzaRFVmCABFAAAoAABAADQGTyNduNgiwKgB' +
      'KgBQyTonqwTSnD8aO1AQAf0JqAAAAAAAAAAAFMDyZdywAAA8AAAAPAAAADwHVBorPPzs2kRVZggARQAAKAABQAA0Bk8iXbjY' +
      'IsCoASoAUMk6J6sE0pw/GjtQEQH9CacAAAAAAAAAABTA8mVfsQAAPAAAADwAAAD87NpEVWY8B1QaKzwIAEUAAChRpUAAQAbx' +
      'fcCoASpduNgiyToAUJw/GjsnqwTTUBAB9gmuAAAAAAAAAAA=',
  },
  {
    id: 'dns',
    title: "DNS query and response",
    layers: "L4/L7",
    fileName: 'dns-sample.pcap',
    format: 'pcap',
    byteLength: 266,
    blurb: "One UDP question and its answer: www.example.com resolves through a CNAME to an A record. The response uses name compression, so the repeated domain costs two bytes instead of seventeen.",
    teaches: [
          "The transaction ID as the only session state a UDP exchange has",
          "Length-prefixed labels — there are no dots on the wire",
          "DNS name compression pointers, visible as 0xC00C in the hex pane",
          "The difference between a DNS TTL (seconds) and an IP TTL (hops)"
    ],
    base64:
      '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAFMDyZQAAAABLAAAASwAAAPzs2kRVZjwHVBorPAgARQAAPU8qQABAEWgKwKgBKsCo' +
      'AQHUMQA1ACnOO48hAQAAAQAAAAAAAAN3d3cHZXhhbXBsZQNjb20AAAEAARTA8mV8VQAAhwAAAIcAAAA8B1QaKzz87NpEVWYI' +
      'AEUAAHkAAQAAQBH298CoAQHAqAEqADXUMQBlU5SPIYGAAAEAAgAAAAADd3d3B2V4YW1wbGUDY29tAAABAAHADAAFAAEAAA4Q' +
      'ABELZXhhbXBsZS1jZG4DbmV0AAtleGFtcGxlLWNkbgNuZXQAAAEAAQAAADwABF242CI=',
  },
  {
    id: 'http',
    title: "HTTP GET request and response (unencrypted)",
    layers: "L5/L6/L7",
    fileName: 'http-sample.pcap',
    format: 'pcap',
    byteLength: 2501,
    blurb: "Two plaintext HTTP exchanges over one persistent connection. The first response is readable HTML; the second is gzip-compressed and chunked, which puts real content on Layer 6.",
    teaches: [
          "One byte range carrying Layers 5, 6 and 7 at once: Cookie, Content-Type, and the request line",
          "Why Content-Encoding: gzip is a presentation-layer concern, not an application one",
          "Chunked transfer encoding as message framing over a stream that has none",
          "Everything — URL, cookie, headers — readable in the ASCII column, because there is no TLS"
    ],
    base64:
      '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAFMDyZQAAAABCAAAAQgAAAPzs2kRVZjwHVBorPAgARQAANCIBQABABiEWwKgBKl24' +
      '2CLClABQDEHZAAAAAACAAvrw1EwAAAIEBbQEAgEDAwcBARTA8mUISAAAQgAAAEIAAAA8B1QaKzz87NpEVWYIAEUAADSIAUAA' +
      'NgbFFV242CLAqAEqAFDClHeyHkAMQdkBgBL+iDqxAAACBAW0BAIBAwMHAQEUwPJlZkgAADwAAAA8AAAA/OzaRFVmPAdUGis8' +
      'CABFAAAoIgJAAEAGISHAqAEqXbjYIsKUAFAMQdkBd7IeQVAQ+vB/GwAAAAAAAAAAFMDyZRhJAACFAQAAhQEAAPzs2kRVZjwH' +
      'VBorPAgARQABdyIDQABABh/RwKgBKl242CLClABQDEHZAXeyHkFQGPrwf24AAEdFVCAvb3NpLWxhYi9pbmRleC5odG1sP2xl' +
      'c3Nvbj1lbmNhcHN1bGF0aW9uIEhUVFAvMS4xDQpIb3N0OiB3d3cuZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IE1vemlsbGEv' +
      'NS4wIChYMTE7IExpbnV4IHg4Nl82NCkgTmV0d29ya2luZ0xhYi8xLjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9u' +
      'L3hodG1sK3htbDtxPTAuOSwqLyo7cT0wLjgNCkFjY2VwdC1MYW5ndWFnZTogZW4tR0IsZW47cT0wLjkNCkFjY2VwdC1FbmNv' +
      'ZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQ29va2llOiBzZXNzaW9uPTdmM2E5YzIxYjQ4ZTVkMDY7IHRoZW1lPWRhcmsNCkNvbm5l' +
      'Y3Rpb246IGtlZXAtYWxpdmUNCg0KFMDyZWqPAAA8AAAAPAAAADwHVBorPPzs2kRVZggARQAAKIgCQAA2BsUgXbjYIsCoASoA' +
      'UMKUd7IeQQxB2lBQEP6IejQAAAAAAAAAABTA8mUMmAAACwIAAAsCAAA8B1QaKzz87NpEVWYIAEUAAf2IA0AANgbDSl242CLA' +
      'qAEqAFDClHeyHkEMQdpQUBj+iEDYAABIVFRQLzEuMSAyMDAgT0sNCkRhdGU6IFRodSwgMTQgTWFyIDIwMjQgMDk6MTU6MDAg' +
      'R01UDQpTZXJ2ZXI6IG5naW54LzEuMjQuMA0KQ29udGVudC1UeXBlOiB0ZXh0L2h0bWw7IGNoYXJzZXQ9dXRmLTgNCkNvbnRl' +
      'bnQtTGVuZ3RoOiAyMjINCkNhY2hlLUNvbnRyb2w6IG1heC1hZ2U9MzAwDQpTZXQtQ29va2llOiBzZXNzaW9uPTdmM2E5YzIx' +
      'YjQ4ZTVkMDY7IFBhdGg9LzsgSHR0cE9ubHkNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCg0KPCFkb2N0eXBlIGh0bWw+Cjxo' +
      'dG1sIGxhbmc9ImVuIj4KICA8aGVhZD48bWV0YSBjaGFyc2V0PSJ1dGYtOCI+PHRpdGxlPk9TSSBMYWI8L3RpdGxlPjwvaGVh' +
      'ZD4KICA8Ym9keT4KICAgIDxoMT5FbmNhcHN1bGF0aW9uPC9oMT4KICAgIDxwPlRoaXMgYm9keSBpcyBMYXllciA3LiBFdmVy' +
      'eXRoaW5nIHdyYXBwZWQgYXJvdW5kIGl0IGlzIGRlbGl2ZXJ5LjwvcD4KICA8L2JvZHk+CjwvaHRtbD4KFMDyZYaYAAA8AAAA' +
      'PAAAAPzs2kRVZjwHVBorPAgARQAAKCIEQABABiEfwKgBKl242CLClABQDEHaUHeyIBZQEPrwe/cAAAAAAAAAABTA8mW3qQAA' +
      'ZQEAAGUBAAD87NpEVWY8B1QaKzwIAEUAAVciBUAAQAYf78CoASpduNgiwpQAUAxB2lB3siAWUBj68AHuAABHRVQgL29zaS1s' +
      'YWIvc3R5bGUuY3NzIEhUVFAvMS4xDQpIb3N0OiB3d3cuZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChY' +
      'MTE7IExpbnV4IHg4Nl82NCkgTmV0d29ya2luZ0xhYi8xLjANCkFjY2VwdDogdGV4dC9jc3MsKi8qO3E9MC4xDQpBY2NlcHQt' +
      'RW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNClJlZmVyZXI6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vb3NpLWxhYi9pbmRleC5o' +
      'dG1sDQpDb29raWU6IHNlc3Npb249N2YzYTljMjFiNDhlNWQwNjsgdGhlbWU9ZGFyaw0KQ29ubmVjdGlvbjoga2VlcC1hbGl2' +
      'ZQ0KDQoUwPJlkfcAAMABAADAAQAAPAdUGis8/OzaRFVmCABFAAGyiARAADYGw5RduNgiwKgBKgBQwpR3siAWDEHbf1AY/og8' +
      'ZQAASFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBUaHUsIDE0IE1hciAyMDI0IDA5OjE1OjAwIEdNVA0KU2VydmVyOiBuZ2lueC8x' +
      'LjI0LjANCkNvbnRlbnQtVHlwZTogdGV4dC9jc3M7IGNoYXJzZXQ9dXRmLTgNCkNvbnRlbnQtRW5jb2Rpbmc6IGd6aXANClRy' +
      'YW5zZmVyLUVuY29kaW5nOiBjaHVua2VkDQpWYXJ5OiBBY2NlcHQtRW5jb2RpbmcNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUN' +
      'Cg0KYTcNCh+LCAAAAAAAAAMlzUsKwyAUQNF5VhHItAYNJQUddiV+nkbqj6ehkZC9l5L55VyVTT9tTo1YGX3ovPbaIJLdP6pM' +
      'lVRAb4WS+uMw78nwiSpGFyp0Dhn5BCsY+xJRovOJ02vY2M19wbut8ZVSEaA1QFKL1D45TuhMGcRrmIPsgKfKaABJANv4sxxj' +
      'zcGbUe+IkNr7vxFFGuOTuxu2lOMafjkXu325AAAADQowDQoNChTA8mUH+AAAPAAAADwAAAD87NpEVWY8B1QaKzwIAEUAACgi' +
      'BkAAQAYhHcCoASpduNgiwpQAUAxB2393siGgUBD68Hk+AAAAAAAAAAAUwPJl048FADwAAAA8AAAA/OzaRFVmPAdUGis8CABF' +
      'AAAoIgdAAEAGIRzAqAEqXbjYIsKUAFAMQdt/d7IhoFAR+vB5PQAAAAAAAAAAFMDyZQDXBQA8AAAAPAAAADwHVBorPPzs2kRV' +
      'ZggARQAAKIgFQAA2BsUdXbjYIsCoASoAUMKUd7IhoAxB24BQEf6IdaQAAAAAAAAAABTA8mVl1wUAPAAAADwAAAD87NpEVWY8' +
      'B1QaKzwIAEUAACgiCEAAQAYhG8CoASpduNgiwpQAUAxB24B3siGhUBD68Hk8AAAAAAAAAAA=',
  },
  {
    id: 'tls',
    title: "TLS 1.3 handshake (ClientHello and ServerHello)",
    layers: "L5/L6",
    fileName: 'tls-sample.pcap',
    format: 'pcap',
    byteLength: 2005,
    blurb: "A full TLS handshake over TCP 443. The ClientHello carries SNI, ALPN, cipher suites and a key share in clear text; after the ServerHello everything turns into opaque Application Data.",
    teaches: [
          "TLS doing real session-layer work: session IDs, tickets, and resumption across connections",
          "Layer 6 in action — cipher and compression negotiation decides how everything above is represented",
          "Why the record layer says \"TLS 1.0\" and the supported_versions extension says 1.3",
          "SNI leaking the destination hostname even though the session is encrypted"
    ],
    base64:
      '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',
  },
  {
    id: 'icmp',
    title: "ICMP echo request and reply (ping)",
    layers: "L3/L4",
    fileName: 'icmp-sample.pcapng',
    format: 'pcapng',
    byteLength: 956,
    blurb: "Three pings and their replies. The replies arrive with TTL 52, so you can count the router hops on the way back and read the round-trip time straight off the timestamps.",
    teaches: [
          "Reading hop count and OS fingerprint from the TTL",
          "How identifier and sequence number match a reply to its request",
          "ICMP sits directly inside IP — there are no ports anywhere in this capture",
          "This file is pcapng rather than classic pcap, so it also exercises the other reader"
    ],
    base64:
      'Cg0NCgAAAFAaKzxNAAEAAP//////////AAEAK1BDQVAtdG8tT1NJIHNhbXBsZTogSUNNUCBlY2hvIHJlcXVlc3QvcmVwbHkA' +
      'AAAAAAAAAFAAAAABAAAAVAABAAAABAAAAAIAA2VuMAAAAwAoU3ludGhldGljIHRlYWNoaW5nIGNhcHR1cmUg4oCUIElDTVAg' +
      'ZWNobwAJAAEGAAAAAAAAAAAAAFQAAAAGAAAAhAAAAAAABhObU2EtAAAAAGIAAABi/OzaRFVmPAdUGis8CABFAABUHEZAAEAB' +
      'JrbAqAEqXbjYIggAMTsKQQABYS/zZQAAAACcGg0AAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1' +
      'NjcAAAAAAIQAAAAGAAAAhAAAAAAABhObU2FlAQAAAGIAAABiPAdUGis8/OzaRFVmCABFAABUAAAAADQBjvxduNgiwKgBKgAA' +
      'OTsKQQABYS/zZQAAAACcGg0AAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1NjcAAAAAAIQAAAAG' +
      'AAAAhAAAAAAABhObU3BvQAAAAGIAAABi/OzaRFVmPAdUGis8CABFAABUHEdAAEABJrXAqAEqXbjYIggAMToKQQACYS/zZQAA' +
      'AACcGg0AAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1NjcAAAAAAIQAAAAGAAAAhAAAAAAABhOb' +
      'U3Co0QAAAGIAAABiPAdUGis8/OzaRFVmCABFAABUAAAAADQBjvxduNgiwKgBKgAAOToKQQACYS/zZQAAAACcGg0AAAAAABAR' +
      'EhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1NjcAAAAAAIQAAAAGAAAAhAAAAAAABhObU3+xgAAAAGIAAABi' +
      '/OzaRFVmPAdUGis8CABFAABUHEhAAEABJrTAqAEqXbjYIggAMTkKQQADYS/zZQAAAACcGg0AAAAAABAREhMUFRYXGBkaGxwd' +
      'Hh8gISIjJCUmJygpKissLS4vMDEyMzQ1NjcAAAAAAIQAAAAGAAAAhAAAAAAABhObU3/soQAAAGIAAABiPAdUGis8/OzaRFVm' +
      'CABFAABUAAAAADQBjvxduNgiwKgBKgAAOTkKQQADYS/zZQAAAACcGg0AAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygp' +
      'KissLS4vMDEyMzQ1NjcAAAAAAIQ=',
  },
  {
    id: 'dhcp',
    title: "DHCP lease (DORA exchange)",
    layers: "L2/L4/L7",
    fileName: 'dhcp-sample.pcap',
    format: 'pcap',
    byteLength: 1458,
    blurb: "Discover, Offer, Request, Acknowledge. Watch a host with no address at all bootstrap itself, using broadcast at Layer 2 and Layer 3 because it has nothing else to work with.",
    teaches: [
          "Why the first packet has source 0.0.0.0 and destination 255.255.255.255",
          "A transaction ID acting as the session, because UDP provides none",
          "DHCP options as type-length-value structures, including the vendor fingerprint",
          "That the same MAC drives the lease — which is why MAC randomisation changes your IP"
    ],
    base64:
      '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAFMDyZQAAAABSAQAAUgEAAP///////zwHVBorPAgARQABRAAAAACAETmqAAAAAP//' +
      '//8ARABDATCpmwEBBgA9HopVAACAAAAAAAAAAAAAAAAAAAAAAAA8B1QaKzwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY4JTYzUBAT0HATwHVBorPAwPbGFiLXdvcmtzdGF0aW9uPAhNU0ZUIDUu' +
      'MDcOAQMGDx8hKywuL3d5+fz/FMDyZQYQAABaAQAAWgEAAP////////zs2kRVZggARQABTAAAAABAEbf4wKgBAf////8AQwBE' +
      'ATi/OQIBBgA9HopVAACAAAAAAADAqAEqwKgBAQAAAAA8B1QaKzwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY4JTYzUBAjYEwKgBATMEAAFRgDoEAACowDsEAAEnUAEE////AAMEwKgBAQYIwKgB' +
      'AQEBAQEPDGxhYi5pbnRlcm5hbP8UwPJlERMAAFQBAABUAQAA////////PAdUGis8CABFAAFGAAAAAIAROagAAAAA/////wBE' +
      'AEMBMtEwAQEGAD0eilUAAIAAAAAAAAAAAAAAAAAAAAAAADwHVBorPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjglNjNQEDPQcBPAdUGis8MgTAqAEqNgTAqAEBDA9sYWItd29ya3N0YXRpb243' +
      'DgEDBg8fISssLi93efn8/xTA8mX4IAAAWgEAAFoBAAD////////87NpEVWYIAEUAAUwAAAAAQBG3+MCoAQH/////AEMARAE4' +
      'vDkCAQYAPR6KVQAAgAAAAAAAwKgBKsCoAQEAAAAAPAdUGis8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGOCU2M1AQU2BMCoAQEzBAABUYA6BAAAqMA7BAABJ1ABBP///wADBMCoAQEGCMCoAQEB' +
      'AQEBDwxsYWIuaW50ZXJuYWz/',
  },
  {
    id: 'ipv6',
    title: "IPv6 over a VLAN trunk, with DNS and ping6",
    layers: "L2/L3",
    fileName: 'ipv6-sample.pcap',
    format: 'pcap',
    byteLength: 523,
    blurb: "The same conversations you already know, one layer down: 802.1Q VLAN tags at Layer 2, 128-bit addresses at Layer 3, an AAAA lookup, and an ICMPv6 echo.",
    teaches: [
          "The 4-byte 802.1Q tag sitting between the source MAC and the EtherType",
          "How the IPv6 header differs: fixed 40 bytes, no checksum, no fragmentation by routers",
          "Payload Length counting only what follows the header, unlike IPv4 Total Length",
          "ICMPv6 checksums covering a pseudo-header, which plain ICMP does not"
    ],
    base64:
      'obLD1AACAAQAAAAAAAAAAAAEAAAAAAABZfLAFAAAAAAAAABvAAAAb/zs2kRVZjwHVBorPIEAABSG3WAAAAAANRFAIAENuBI0' +
      'VngAAAAAAAAAoSABSGBIYAAAAAAAAAAAiIjgTgA1ADULQSt8ASAAAQAAAAAAAQRpcHY2B2V4YW1wbGUDb3JnAAAcAAEAACkE' +
      '0AAAAAAAAGXywBQAAF43AAAAgAAAAIA8B1QaKzz87NpEVWaBAAAUht1gAAAAAEYROSABSGBIYAAAAAAAAAAAiIggAQ24EjRW' +
      'eAAAAAAAAAChADXgTgBGHOsrfIGAAAEAAQAAAAAEaXB2NgdleGFtcGxlA29yZwAAHAABwAwAHAABAAABLAAQIAENuBI0VngA' +
      'AAAAAAAPDWXywBQAAGFGAAAAYgAAAGL87NpEVWY8B1QaKzyBAAAUht1gAAAAACg6QCABDbgSNFZ4AAAAAAAAAKEgAQ24EjRW' +
      'eAAAAAAAAA8NgAC0cxssAAEwMTIzNDU2Nzg5Ojs8PT4/MDEyMzQ1Njc4OTo7PD0+P2XywBQAAGe3AAAAYgAAAGI8B1QaKzz8' +
      '7NpEVWaBAAAUht1gAAAAACg6QCABDbgSNFZ4AAAAAAAADw0gAQ24EjRWeAAAAAAAAAChgQCzcxssAAEwMTIzNDU2Nzg5Ojs8' +
      'PT4/MDEyMzQ1Njc4OTo7PD0+Pw==',
  },
  {
    id: 'wifi',
    title: "Wi-Fi monitor mode: real Layer 1 measurements",
    layers: "L1/L2",
    fileName: 'wifi-sample.pcapng',
    format: 'pcapng',
    byteLength: 1588,
    blurb: "The one capture type that carries genuine physical-layer data. A radiotap header records what the radio actually measured — channel frequency, signal strength in dBm, antenna, modulation and coding — as real bytes you can highlight in the hex pane.",
    teaches: [
          "Layer 1 with measured values: 2437 MHz, -38 dBm, MCS 7, 400 ns guard interval",
          "An 802.11 header with up to four address fields whose meaning depends on two flag bits",
          "Beacons, probe requests and acknowledgements: frames that exist only to manage a shared medium",
          "A retry with a bad FCS at -84 dBm, which is what a struggling client looks like before TCP notices",
          "pcapng per-packet metadata: direction, reception type and packet comments"
    ],
    base64:
      'Cg0NCgAAAHAaKzxNAAEAAP//////////AAEATFBDQVAtdG8tT1NJIHNhbXBsZTogV2ktRmkgbW9uaXRvciBtb2RlIHdpdGgg' +
      'cmFkaW90YXAgcGh5c2ljYWwtbGF5ZXIgbWV0YWRhdGEAAAAAAAAAcAAAAAEAAAC0AH8AAAAEAAAAAgAId2xhbjBtb24AAwAp' +
      'QXRoZXJvcyBBUjkyODAgaW4gbW9uaXRvciBtb2RlLCBjaGFubmVsIDYAAAAACAAIAAAAABHhowAACQABCQAAAAANAAEAAAAA' +
      'AAwAE0xpbnV4IDYuOC4wIChhdGg5aykAAA8AJVF1YWxjb21tIEF0aGVyb3MgQVI5MjgwIDgwMi4xMWEvYi9nL24AAAAAAAAA' +
      'AAAAtAAAAAYAAADkAAAAABe8lr2zl8gAAAAAaQAAAGkAABkAbwgAABQjZisAAAAAAAKFCaAA2qEAgAAAAP////////zs2kRV' +
      'Zvzs2kRVZlCDFCNmKwAAAABkADEEAAdPU0ktTGFiAQiChIuWDBIYJAMBBjAUAQAAD6wEAQAAD6wEAQAAD6wCAAAAAAAAAgAE' +
      'AAAADQABAEZCZWFjb246IHRoZSBhY2Nlc3MgcG9pbnQgYW5ub3VuY2luZyB0aGUgY2VsbCBhYm91dCB0ZW4gdGltZXMgYSBz' +
      'ZWNvbmQuAAAAAAAAAAAA5AAAAAYAAABsAAAAABe8lr22FtoAAAAAPQAAAD0AABkAbwgAAK7GZisAAAAAAAKFCaAAx6EAQAAA' +
      'AP///////zwHVBorPP///////2CDAAABCIKEi5YMEhgkAAAAAAIABAAAAA0AAAAAAAAAbAAAAAYAAACYAAAAABe8lr22HqkA' +
      'AAAAaQAAAGkAABkAbwgAAK7IZisAAAAAAAKFCaAA2aEAUAAAADwHVBorPPzs2kRVZvzs2kRVZnCDrshmKwAAAABkADEEAAdP' +
      'U0ktTGFiAQiChIuWDBIYJAMBBjAUAQAAD6wEAQAAD6wEAQAAD6wCAAAAAAAAAgAEAAAABQAAAAAAAACYAAAABgAAAOQAAAAA' +
      'F7yWvb0t6QAAAABzAAAAcwAAFABqCAgAAACFCcAAyaEBBwUHiAEsAPzs2kRVZjwHVBorPPzs2kRVZoCDAACqqgMAAAAIAEUA' +
      'AD18EUAAQBE7I8CoASrAqAEByBgANQApN9dRrQEAAAEAAAAAAAADbGFiB2V4YW1wbGUDbmV0AAABAAEAAAIABAAAAAYAAQA/' +
      'VGhlIG9ubHkgODAyLjExIGZyYW1lIHR5cGUgdGhhdCBjYXJyaWVzIGFueXRoaW5nIGFib3ZlIExheWVyIDIuAAAAAAAAAADk' +
      'AAAABgAAAKAAAAAAF7yWvb0uKAAAAAAbAAAAGwAAEQBuCAAAADCFCcAA2qEA1AAAADwHVBorPAAAAgAEAAAABQABAFNMYXll' +
      'ciAyIHJlbGlhYmlsaXR5OiBldmVyeSB1bmljYXN0IFdpLUZpIGZyYW1lIGlzIGFja25vd2xlZGdlZCB3aXRoaW4gbWljcm9z' +
      'ZWNvbmRzLgAAAAAAAAAAoAAAAAYAAAD0AAAAABe8lr29XYQAAAAAcwAAAHMAABQAaggIAEAAhQnAAKyhAQcAAIgJLAD87NpE' +
      'VWY8B1QaKzz87NpEVWaAgwAAqqoDAAAACABFAAA9fBFAAEAROyPAqAEqwKgBAcgYADUAKTfXUa0BAAABAAAAAAAAA2xhYgdl' +
      'eGFtcGxlA25ldAAAAQABAAACAAQAAAARAAEAT0hhcmR3YXJlIGZsYWdnZWQgYSBiYWQgRkNTOiBtb25pdG9yIG1vZGUgaGVh' +
      'cnMgZnJhbWVzIGl0IGNhbm5vdCBkZWNvZGUgY2xlYW5seS4AAAAAAAAAAPQAAAAGAAAAsAAAAAAXvJa9vp4DAAAAAIMAAACD' +
      'AAAUAGoICAAAAIUJwADaoQAHBQ+IAiwAPAdUGis8/OzaRFVm/OzaRFVmkIMAAKqqAwAAAAgARQAATQACAABAEfciwKgBAcCo' +
      'ASoANcgYADkzs1GtgYAAAQABAAAAAANsYWIHZXhhbXBsZQNuZXQAAAEAAcAMAAEAAQAAAHgABMCoAVAAAAIABAAAAAUAAAAA' +
      'AAAAsA==',
  },
];

/** Decode a bundled sample into an ArrayBuffer, exactly as if it were dropped in. */
export function decodeSample(sample: SampleCapture): ArrayBuffer {
  const binary = atob(sample.base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
}
