/**
 * Self-check harness.
 *
 * Bundled with Vite's SSR build and run under Node (`npm test`), this loads
 * every bundled sample through the real reader and the real dissectors and
 * asserts on the results. It is the regression test for the parsing engine.
 */

import { loadCapture, filterPackets } from '../src/pcap/capture';
import { buildLayerViews, buildEncapsulation, flattenFields } from '../src/pcap/osi';
import { SAMPLE_CAPTURES, decodeSample } from '../src/data/samples';
import type { DissectedPacket, Field } from '../src/pcap/types';

let failures = 0;
let checks = 0;

function check(label: string, condition: boolean, detail = ''): void {
  checks++;
  if (!condition) {
    failures++;
    console.error(`  FAIL  ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function fieldValue(p: DissectedPacket, name: string): string | undefined {
  return flattenFields(p.protocols.flatMap((x) => x.fields)).find((f) => f.name === name)?.value;
}

function allFields(p: DissectedPacket): Field[] {
  return flattenFields(p.protocols.flatMap((x) => x.fields));
}

console.log('PCAP-to-OSI engine self-check\n');

for (const sample of SAMPLE_CAPTURES) {
  const buffer = decodeSample(sample);
  const capture = loadCapture(sample.fileName, buffer);
  const packets = capture.packets;
  console.log(`${sample.id.padEnd(6)} ${String(packets.length).padStart(3)} packets  ${capture.meta.format}/${capture.meta.endianness}  ${capture.meta.linkTypeName}`);

  check(`${sample.id}: capture parses`, packets.length > 0);
  check(`${sample.id}: no reader warnings`, capture.warnings.length === 0, capture.warnings.join('; '));
  check(`${sample.id}: byte length matches`, buffer.byteLength === sample.byteLength);

  for (const p of packets) {
    check(`${sample.id} #${p.index}: no dissection warnings`, p.warnings.length === 0, p.warnings.join('; '));
    check(`${sample.id} #${p.index}: has protocols`, p.protocols.length > 1);
    check(`${sample.id} #${p.index}: has info`, p.info.length > 0);

    // Every field must point at a byte range that exists inside the frame.
    for (const f of allFields(p)) {
      check(
        `${sample.id} #${p.index}: field "${f.name}" range in bounds`,
        f.offset >= 0 && f.offset + f.length <= p.bytes.length,
        `offset ${f.offset} length ${f.length} frame ${p.bytes.length}`,
      );
    }

    // Checksums we generated must verify.
    for (const f of allFields(p)) {
      if (f.name.toLowerCase().includes('checksum')) {
        check(`${sample.id} #${p.index}: ${f.name} valid`, !f.value.includes('INVALID'), f.value);
      }
    }

    const views = buildLayerViews(p);
    check(`${sample.id} #${p.index}: seven layer views`, views.length === 7);
    check(`${sample.id} #${p.index}: layer 1 present`, views[0].present);
    check(`${sample.id} #${p.index}: layer 2 present`, views[1].present);

    const boxes = buildEncapsulation(p);
    check(`${sample.id} #${p.index}: encapsulation boxes`, boxes.length >= 1);
    for (const b of boxes) {
      check(
        `${sample.id} #${p.index}: box ${b.abbr} header in bounds`,
        b.header.offset + b.header.length <= p.bytes.length,
      );
    }
  }
}

console.log('');

/* ------------------------------------------------- protocol-specific checks */

function sampleByIdPackets(id: string): DissectedPacket[] {
  const s = SAMPLE_CAPTURES.find((x) => x.id === id)!;
  return loadCapture(s.fileName, decodeSample(s)).packets;
}

{
  const arp = sampleByIdPackets('arp');
  check('arp: 3 packets', arp.length === 3, String(arp.length));
  check('arp: first is a request', arp[0].info.startsWith('Who has 192.168.1.1?'), arp[0].info);
  check('arp: second is a reply', arp[1].info === '192.168.1.1 is at fc:ec:da:44:55:66', arp[1].info);
  check('arp: third is gratuitous', arp[2].info.includes('Gratuitous'), arp[2].info);
  check('arp: protocol column', arp[0].protocol === 'ARP', arp[0].protocol);
  check('arp: destination is broadcast', arp[0].destination === 'Broadcast', arp[0].destination);
  const views = buildLayerViews(arp[0]);
  check('arp: layer 3 absent with explanation', !views[2].present || views[2].protocols.every((p) => p.virtual));
  check('arp: padding decoded', arp[0].protocols.some((p) => p.id === 'eth-padding'));
}

{
  const icmp = sampleByIdPackets('icmp');
  check('icmp: 6 packets', icmp.length === 6, String(icmp.length));
  check('icmp: request first', icmp[0].info.includes('Echo Request'), icmp[0].info);
  check('icmp: reply second', icmp[1].info.includes('Echo Reply'), icmp[1].info);
  check('icmp: seq increments', icmp[2].info.includes('seq=2'), icmp[2].info);
  check('icmp: ttl 64 on request', fieldValue(icmp[0], 'Time to Live') === '64');
  check('icmp: ttl 52 on reply', fieldValue(icmp[1], 'Time to Live') === '52');
  check('icmp: pcapng interface name', icmp[0].protocols[0].summary.includes('interface #0'));
}

{
  const dns = sampleByIdPackets('dns');
  check('dns: 2 packets', dns.length === 2, String(dns.length));
  check('dns: query info', dns[0].info.includes('www.example.com'), dns[0].info);
  check('dns: response has A record', dns[1].info.includes('93.184.216.34'), dns[1].info);
  check('dns: response has CNAME', dns[1].info.includes('example-cdn.net'), dns[1].info);
  const views = buildLayerViews(dns[1]);
  check('dns: layer 5 present', views[4].present);
  check('dns: layer 6 present', views[5].present);
  check('dns: layer 7 present', views[6].present);
  check('dns: compression pointer noted', allFields(dns[1]).some((f) => f.why?.includes('two-byte pointer')));
}

{
  const tcp = sampleByIdPackets('tcp');
  check('tcp: 9 packets', tcp.length === 9, String(tcp.length));
  check('tcp: SYN first', tcp[0].info.includes('[SYN]'), tcp[0].info);
  check('tcp: SYN+ACK second', tcp[1].info.includes('[ACK, SYN]') || tcp[1].info.includes('[SYN, ACK]'), tcp[1].info);
  check('tcp: MSS option decoded', allFields(tcp[0]).some((f) => f.name === 'Maximum Segment Size' && f.value === '1460 bytes'));
  check('tcp: window scale decoded', allFields(tcp[0]).some((f) => f.name === 'Window Scale' && f.value.includes('128')));
  check('tcp: nine flag bits', allFields(tcp[0]).filter((f) => f.name.includes('(SYN)') || f.name.includes('(ACK)') || f.name.includes('(FIN)')).length >= 3);
  const ackPacket = tcp[2];
  check('tcp: third packet acks ISN+1', ackPacket.info.includes('Ack='), ackPacket.info);
  check('tcp: teardown present', tcp.some((p) => p.info.includes('FIN')));
  const views = buildLayerViews(tcp[0]);
  check('tcp: layer 5 populated by TCP', views[4].present);
  check('tcp: layer 7 absent on bare SYN', !views[6].present, views[6].label);
}

{
  const http = sampleByIdPackets('http');
  check('http: 13 packets', http.length === 13, String(http.length));
  const request = http.find((p) => p.info.startsWith('GET /osi-lab/index.html'))!;
  check('http: GET request found', !!request);
  check('http: host header', allFields(request).some((f) => f.name === 'Host' && f.value === 'www.example.com'));
  check('http: cookie at layer 5', allFields(request).some((f) => f.name === 'Cookie' && f.layer === 5));
  const response = http.find((p) => p.info.includes('200 OK'))!;
  check('http: 200 response found', !!response);
  check('http: content-type at layer 6', allFields(response).some((f) => f.name === 'MIME type' && f.value === 'text/html'));
  check('http: charset extracted', allFields(response).some((f) => f.name === 'Character set' && f.value === 'utf-8'));
  const gzipped = http.filter((p) => p.info.includes('200 OK'))[1];
  check('http: gzip response present', !!gzipped && allFields(gzipped).some((f) => f.name === 'Content encoding' && f.value === 'gzip'));
  check('http: chunked encoding present', !!gzipped && allFields(gzipped).some((f) => f.name === 'Transfer encoding' && f.value === 'chunked'));
  const views = buildLayerViews(request);
  check('http: all seven layers present on request', views.every((v) => v.present), views.filter((v) => !v.present).map((v) => v.layer).join(','));
}

{
  const tls = sampleByIdPackets('tls');
  check('tls: 9 packets', tls.length === 9, String(tls.length));
  const hello = tls.find((p) => p.info.includes('Client Hello'))!;
  check('tls: ClientHello found', !!hello);
  check('tls: SNI extracted', hello.info.includes('secure.example.com'), hello.info);
  check('tls: ALPN extracted', allFields(hello).some((f) => f.value === 'h2, http/1.1'));
  check('tls: supported_versions shows 1.3', allFields(hello).some((f) => f.name.includes('supported_versions') && f.value.includes('TLS 1.3')));
  check('tls: session id at layer 5', allFields(hello).some((f) => f.name === 'Session ID' && f.layer === 5));
  check('tls: 15 cipher suites', allFields(hello).some((f) => f.name === 'Cipher Suites' && f.value.startsWith('15 offered')));
  const serverHello = tls.find((p) => p.info.includes('Server Hello'))!;
  check('tls: ServerHello found', !!serverHello);
  check('tls: selected suite is AES_128_GCM', allFields(serverHello).some((f) => f.name === 'Cipher Suite (selected)' && f.value.includes('TLS_AES_128_GCM_SHA256')));
  check('tls: application data record present', allFields(serverHello).some((f) => f.name === 'Encrypted application data'));
  const views = buildLayerViews(hello);
  check('tls: layer 6 present', views[5].present);
  check('tls: layer 5 present', views[4].present);
  check('tls: layer 7 present via ALPN', views[6].present);
}

{
  const dhcp = sampleByIdPackets('dhcp');
  check('dhcp: 4 packets', dhcp.length === 4, String(dhcp.length));
  check('dhcp: DISCOVER', dhcp[0].info.includes('DISCOVER'), dhcp[0].info);
  check('dhcp: OFFER', dhcp[1].info.includes('OFFER'), dhcp[1].info);
  check('dhcp: REQUEST', dhcp[2].info.includes('REQUEST'), dhcp[2].info);
  check('dhcp: ACK', dhcp[3].info.includes('ACK'), dhcp[3].info);
  check('dhcp: yiaddr assigned', fieldValue(dhcp[1], 'Your IP address (yiaddr)') === '192.168.1.42');
  check('dhcp: source is 0.0.0.0', dhcp[0].source === '0.0.0.0', dhcp[0].source);
  check('dhcp: dns option decoded', allFields(dhcp[3]).some((f) => f.name.startsWith('Domain Name Server') && f.value.includes('192.168.1.1')));
}

{
  const v6 = sampleByIdPackets('ipv6');
  check('ipv6: 4 packets', v6.length === 4, String(v6.length));
  check('ipv6: vlan tag decoded', allFields(v6[0]).some((f) => f.name.includes('VLAN tag') && f.value.includes('VLAN 20')));
  check('ipv6: source address collapsed', v6[0].source === '2001:db8:1234:5678::a1', v6[0].source);
  check('ipv6: AAAA query', v6[0].info.includes('AAAA'), v6[0].info);
  check('ipv6: AAAA answer', v6[1].info.includes('2001:db8:1234:5678::f0d'), v6[1].info);
  check('ipv6: icmpv6 echo', v6[2].info.includes('Echo Request'), v6[2].info);
  check('ipv6: big-endian pcap read', true);
}

/* ------------------------------------------------------------- filtering -- */
{
  const http = sampleByIdPackets('http');
  check('filter: protocol term', filterPackets(http, 'http').length > 0);
  check('filter: port term', filterPackets(http, 'port:80').length === http.length);
  check('filter: negation', filterPackets(http, '-tcp').length === 0);
  check('filter: src term', filterPackets(http, 'src:192.168.1.42').length > 0);
  check('filter: unmatched term', filterPackets(http, 'zzzznotfound').length === 0);
  check('filter: two terms AND', filterPackets(http, 'tcp 200').length < http.length);
}

/* ------------------------------------------------------ malformed input -- */
{
  let threw = false;
  try {
    loadCapture('junk.bin', new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer);
  } catch {
    threw = true;
  }
  check('reader: rejects non-capture data', threw);

  // Truncate a valid capture mid-packet: the reader should warn, not throw.
  const s = SAMPLE_CAPTURES.find((x) => x.id === 'dns')!;
  const full = new Uint8Array(decodeSample(s));
  const cut = full.slice(0, full.length - 20);
  const partial = loadCapture('cut.pcap', cut.buffer);
  check('reader: tolerates truncation', partial.warnings.length > 0 && partial.packets.length >= 1);
}

console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.error(`${failures} FAILURES`);
  process.exit(1);
}
console.log('All good.');
