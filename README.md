# PCAP-to-OSI Interactive Visualizer

A teaching tool that takes a real packet capture and pulls it apart into the
seven OSI layers — byte by byte, field by field, with a plain-English
explanation of what every field does and why its value in *this* packet
matters.

It is a single-page app that runs entirely in the browser. There is no backend,
no upload, no telemetry and no network access at runtime: the capture file is
read with `FileReader`, parsed in JavaScript, and never leaves the machine.
Load the page once and it keeps working offline for the rest of the lesson.

```bash
npm install
npm run dev        # http://localhost:5173
```

That is the whole setup. Node 20.19+ (or 22.12+) is the only prerequisite.

---

## What it does

**Ingestion.** Drag and drop a `.pcap` or `.pcapng` file, or click to browse.
Eight lab captures are bundled so a student with no capture file of their own
can start immediately.

**Dissection.** Every frame is decoded from the link layer upwards and each
field is tagged with the OSI layer it belongs to, plus the exact byte range it
occupies inside the frame. That byte range is what makes everything else work.

**Four synchronised views:**

| View | What it shows |
| --- | --- |
| Packet list | No., time, source, destination, protocol, length, info — with a quick filter |
| OSI layer inspector | All seven layers, always, with the fields that belong to each |
| Encapsulation diagram | Nested "Russian doll" boxes, switchable between Tx (encapsulate) and Rx (decapsulate) |
| Hex / ASCII pane | The raw bytes, tinted by OSI layer, highlighting in sync with whatever you hover |

Hovering anywhere highlights the same bytes everywhere. Hover a field in the
inspector and its bytes light up in the hex pane; hover a byte in the hex pane
and the inspector scrolls to and highlights the field that owns it. Click a
field to pin its full explanation in the side drawer.

**Teacher Mode** (on by default) adds two paragraphs to every field:

- *What it does* — the static definition, from a curated glossary.
- *Why this value matters* — computed from the actual bytes. TTL 52 gets a hop
  count and an OS-fingerprint reading; a SYN with no ACK gets an explanation of
  connection initiation; an empty TLS session ID explains what resumption would
  have looked like.

---

## Protocol coverage

**Capture containers**
- Classic libpcap, all four magic-number variants (big/little endian ×
  microsecond/nanosecond timestamps)
- pcapng: Section Header, Interface Description, Enhanced Packet, Simple Packet
  and the obsolete Packet block, with per-interface timestamp resolution

**Link types**
Ethernet II / IEEE 802.3 (with 802.1Q and QinQ VLAN stacks), raw IPv4, raw
IPv6, Linux cooked capture (SLL and SLL2), BSD loopback.

**Protocols**
ARP/RARP · IPv4 (options, fragmentation, DSCP/ECN, checksum verification) ·
IPv6 (extension-header chain) · TCP (all nine flags expanded to bits, MSS,
window scale, SACK, timestamps, pseudo-header checksum verification) · UDP ·
ICMP · ICMPv6 · DNS (full name decompression, all common record types) ·
mDNS · DHCP/BOOTP (option TLVs) · HTTP/1.x (request line, status line, headers,
body) · TLS 1.0–1.3 (records, ClientHello/ServerHello, SNI, ALPN,
supported_versions, key_share, cipher suites, session tickets).

Anything not recognised still gets a byte dump, an ASCII rendering, and an
explanation of what can still be inferred from the layers below.

---

## The seven layers, honestly

The hard part of teaching OSI with real captures is that TCP/IP does not
implement the model. Rather than papering over that, the tool makes the
mismatch the lesson.

**Layer 1 is synthesised, and says so.** A PCAP file contains no Layer 1 data
at all: the preamble, start-of-frame delimiter, line coding, voltages or RF
modulation, and usually the frame check sequence, are consumed and stripped by
the network adapter before the capture driver ever sees the frame. What a
capture *does* contain is metadata about the frame's physical arrival, and that
is what this layer shows — wire arrival timestamp, captured length versus wire
length, the capture interface, the link-layer encapsulation, and the
serialisation time those bits occupied on a 1 Gbit/s and a 100 Mbit/s link. A
dedicated field spells out exactly what is missing and why.

**Layers 5 and 6 are populated from whatever is actually doing the job.**
TCP/IP has no separate session or presentation protocol, so the tool shows
which mechanism has absorbed those duties in each packet:

- Layer 5 gets the TCP four-tuple and dialogue state (establishing, transferring,
  tearing down), TLS session IDs and tickets, DNS and DHCP transaction IDs, and
  HTTP cookies and `Connection: keep-alive`.
- Layer 6 gets TLS records and cipher/compression negotiation, HTTP
  `Content-Type`, charset, `Content-Encoding` and `Transfer-Encoding`, the DNS
  binary wire format with its pointer compression, and the ASN.1 BER/DER
  structure of an X.509 certificate chain.

**When a layer really is empty, it says why.** A bare TCP ACK has no Layer 7 —
and the inspector explains that control segments exist purely to run the
transport state machine. An ARP frame has no Layer 3 — and the inspector points
out that ARP carries IP addresses without being carried inside IP, which is
exactly why an ARP frame can never be routed off the local segment.

---

## Bundled lab captures

| Capture | Layers | What it is for |
| --- | --- | --- |
| ARP address resolution | L2 | Broadcast question, unicast answer, gratuitous ARP, Ethernet padding |
| TCP handshake and teardown | L4 | SYN/SYN-ACK/ACK, one data segment, the four-message close, options negotiated only in the handshake |
| DNS query and response | L4/L7 | Transaction IDs, length-prefixed labels, CNAME → A, name compression |
| HTTP GET request and response | L5/L6/L7 | Two exchanges on one connection: readable HTML, then gzip + chunked |
| TLS 1.3 handshake | L5/L6 | SNI, ALPN, cipher suites, key share, then opaque Application Data |
| ICMP echo request and reply | L3/L4 | Hop counting from TTL, identifier/sequence matching — and it is a **pcapng** file |
| DHCP lease (DORA) | L2/L4/L7 | Bootstrapping from 0.0.0.0, option TLVs, transaction as session |
| IPv6 over a VLAN trunk | L2/L3 | 802.1Q tags, the IPv6 header, AAAA lookup, ICMPv6 echo |

These are **synthetic**. Every frame was constructed byte by byte from the
relevant RFCs, with real Internet checksums and real TCP sequence arithmetic,
by `tools/gen-samples.mjs`. Nothing was recorded from a real network, so there
is no third-party traffic in the classroom material — and the files still open
correctly in Wireshark and tshark. Rebuild them with `npm run samples`.

---

## Quick filter

The filter box is deliberately not a Wireshark display-filter clone. Terms are
space-separated and ANDed; a leading `-` negates.

```
tcp                     any field mentions TCP
443                     any field mentions 443
port:443                specifically a port
src:192.168.1.42        source address
dst:93.184.216.34       destination address
ip:192.168.1.42         either address
proto:dns               protocol column
info:syn                info column
tcp -ack                TCP frames that are not pure ACKs
```

Protocol chips under the toolbar do the same thing in one click.

**Keyboard:** `↑`/`↓` walk the filtered list, `/` focuses the filter, `Esc`
unpins the current field.

---

## Architecture and the decisions behind it

### Why 100% client-side

The brief allowed a Python backend. A browser-only SPA won on three grounds
that matter in a classroom:

1. **Privacy is structural, not promised.** A capture is some of the most
   sensitive data a student can hold — credentials, internal topology, someone
   else's traffic. With no server there is nothing to trust: the bytes physically
   cannot leave the tab.
2. **Zero install friction.** `npm install && npm run dev`, or just open the
   built `dist/` from a USB stick. No Python version, no virtualenv, no
   `libpcap` headers, no admin rights.
3. **It works offline.** Built with a relative `base`, `dist/` is a folder of
   static files that runs from `file://`-adjacent hosting or any web server, in
   a lab with no internet.

### Why a hand-written parser instead of a library or WebAssembly

The reader and every dissector are written from scratch in TypeScript. That is
roughly 2,500 lines that a WASM build of libpcap or a bundled npm parser could
have replaced, and it was still the right call:

- **The field model is the product.** The teaching value comes from every field
  carrying its exact byte offset, its bit range, its OSI layer, and its
  explanation. No general-purpose parser emits that shape, so the alternative
  was a translation layer over someone else's output — more code than writing
  the dissectors, and less control.
- **Auditability.** An instructor can read `src/pcap/dissect/tcp.ts` and check
  that what the tool claims about a flag is true. A WASM blob cannot be read in
  a lecture.
- **Size and startup.** The whole app is ~370 KB of JavaScript (125 KB gzipped)
  with two runtime dependencies, React and React DOM. A WASM decoder would have
  been several times that before the UI.
- **Honest failure.** Malformed input produces a named warning attached to the
  packet, not an opaque crash inside a foreign runtime.

### Stack

Vite 7 · React 19 · TypeScript 5 (strict) · Tailwind CSS 4. React earns its
place here because four panes must stay synchronised on a single hover; the
alternative was hand-rolling that coordination.

### Code layout

```
src/
  pcap/
    types.ts          the field/protocol/packet model everything shares
    bytes.ts          byte and formatting helpers, the RFC 1071 checksum
    reader.ts         pcap and pcapng container parsing
    linktypes.ts      LINKTYPE_* names
    capture.ts        read + dissect + filter
    osi.ts            maps tagged fields onto the seven layers and the diagram
    dissect/
      index.ts        entry point, link-type dispatch, synthesised Layer 1
      context.ts      shared dissection state and the field builder
      ethernet.ts     Ethernet II / 802.3, VLAN stacks, ARP
      ipv4.ts ipv6.ts network layer, options, extension headers
      tcp.ts udp.ts icmp.ts    transport layer and checksum verification
      application.ts  port-directed and content-sniffing dispatch
      http.ts dns.ts tls.ts dhcp.ts
      ports.ts oui.ts well-known ports and vendor prefixes
  data/
    glossary.ts       the "what does this field do" dictionary
    samples.ts        GENERATED — the bundled captures, base64-encoded
  components/         PacketTable, OsiInspector, EncapsulationDiagram,
                      HexView, FieldDrawer, CaptureLoader
tools/
  lib-pcap.mjs        frame construction helpers
  gen-samples.mjs     builds the bundled captures
tests/
  harness.ts          engine self-check (npm test)
```

### Design details worth knowing

- **Every field is anchored to bytes.** `offset` and `length` are absolute
  coordinates inside the frame, so the hex pane highlights without knowing
  anything about protocols. Sub-byte fields add a `bits` range, rendered as a
  bit diagram in the drawer.
- **Virtual layers.** Synthesised Layer 1 metadata and Layer 5/6 commentary are
  marked `virtual`: they appear in the inspector but are skipped by the
  encapsulation diagram, which only nests bytes that really exist.
- **Ethernet padding is not payload.** A 54-byte TCP ACK arrives inside a
  60-byte frame. The transport dissectors bound themselves by the IP header's
  length field, not by the frame, so padding is never mistaken for data and
  checksums verify correctly. (This was a real bug the test harness caught.)
- **Checksums are verified, not just displayed** — IPv4 headers, ICMP, and
  TCP/UDP including the IPv4 and IPv6 pseudo-headers. When one fails, the
  explanation mentions NIC checksum offload before it suggests corruption,
  because that is overwhelmingly the real cause in a capture taken on the
  sending host.
- **The packet list is windowed** by hand, so a capture with tens of thousands
  of frames stays responsive on modest lab hardware. Reading stops at 200,000
  packets rather than locking up the tab.
- **Colour is a teaching device.** One hue per OSI layer, used identically in
  the protocol column, the inspector, the diagram and every byte of the hex
  dump.

---

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Dev server with hot reload |
| `npm run build` | Type-check, then build to `dist/` |
| `npm run preview` | Serve the production build |
| `npm test` | Run the engine self-check |
| `npm run typecheck` | Type-check only |
| `npm run samples` | Regenerate the bundled captures |
| `npm run check` | Type-check, test and build |

### Tests

`npm test` bundles `tests/harness.ts` with Vite's SSR build and runs it under
Node. It loads all eight bundled captures through the real reader and the real
dissectors and asserts roughly 3,500 things, among them:

- every capture parses with no reader or dissector warnings;
- every field's byte range lies inside its frame — no dangling highlights;
- every checksum the generator computed verifies through the dissector, in both
  directions, which cross-checks the two independent implementations;
- protocol-specific expectations (ARP opcodes, TCP option values, DNS
  compression, HTTP header layering, TLS SNI/ALPN extraction, DHCP options,
  IPv6 address formatting, VLAN tags);
- filter behaviour, including negation and field-scoped terms;
- malformed input is rejected with a message, and a truncated capture produces
  a warning rather than an exception.

---

## Limitations

Worth being straight about, since students will find these:

- **No TCP stream reassembly.** Each segment is dissected on its own. An HTTP
  response split across segments is decoded from the segment that carries the
  headers; the rest shows as continuation data.
- **No decryption.** TLS Application Data stays opaque. Key-log-file support
  (`SSLKEYLOGFILE`) is the obvious next feature.
- **No IP fragment reassembly.** Fragments after the first are flagged and
  explained rather than stitched back together.
- **Compressed captures** (`.pcap.gz`) must be decompressed first.
- **HTTP/2 and HTTP/3** are not decoded; HTTP/2 over TLS shows as encrypted
  Application Data, with ALPN telling you what is inside.
- **The OUI table is deliberately small** — enough to make the point about
  vendor prefixes and locally administered addresses, not a full IEEE registry.

## License

MIT.
