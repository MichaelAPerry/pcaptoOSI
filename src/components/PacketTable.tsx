import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { DissectedPacket, OsiLayer } from '../pcap/types';

const ROW_HEIGHT = 26;
const OVERSCAN = 12;

interface Props {
  packets: DissectedPacket[];
  totalCount: number;
  selectedIndex: number | null;
  onSelect: (packet: DissectedPacket) => void;
}

/**
 * Protocol colours reuse the layer palette, so the protocol column silently
 * teaches which layer a protocol belongs to.
 */
const PROTOCOL_LAYER: Record<string, OsiLayer> = {
  ARP: 2,
  RARP: 2,
  Ethernet: 2,
  PAD: 2,
  LOOPBACK: 2,
  SLL: 2,
  SLL2: 2,
  IPv4: 3,
  IPv6: 3,
  'IPv6-EXT': 3,
  TCP: 4,
  UDP: 4,
  ICMP: 4,
  ICMPv6: 4,
  TLS: 6,
  HTTP: 7,
  DNS: 7,
  mDNS: 7,
  DHCP: 7,
  DATA: 7,
};

export function protocolLayer(name: string): OsiLayer {
  return PROTOCOL_LAYER[name] ?? 7;
}

/**
 * The packet list.
 *
 * Windowed by hand rather than with a dependency: a classroom capture can hold
 * tens of thousands of frames and rendering them all would make selection feel
 * sticky on the modest hardware these labs usually run on.
 */
export function PacketTable({ packets, totalCount, selectedIndex, onSelect }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(400);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const observer = new ResizeObserver(() => setViewportHeight(el.clientHeight));
    observer.observe(el);
    setViewportHeight(el.clientHeight);
    return () => observer.disconnect();
  }, []);

  // Keep the selected row visible when selection moves via the keyboard.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || selectedIndex === null) return;
    const position = packets.findIndex((p) => p.index === selectedIndex);
    if (position < 0) return;
    const top = position * ROW_HEIGHT;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + ROW_HEIGHT > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW_HEIGHT - el.clientHeight;
  }, [selectedIndex, packets]);

  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const visible = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2;
  const slice = packets.slice(first, first + visible);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between border-b px-3 py-2 hairline">
        <h2 className="text-[12px] font-semibold tracking-wide uppercase dim">Packets</h2>
        <span className="text-[11px] faint">
          {packets.length === totalCount
            ? `${totalCount} frame${totalCount === 1 ? '' : 's'}`
            : `${packets.length} of ${totalCount} shown`}
        </span>
      </div>

      <div className="grid shrink-0 grid-cols-[52px_84px_150px_150px_74px_58px_1fr] gap-2 border-b px-3 py-1.5 text-[10px] font-semibold tracking-wide uppercase hairline faint">
        <span>No.</span>
        <span>Time</span>
        <span>Source</span>
        <span>Destination</span>
        <span>Protocol</span>
        <span className="text-right">Length</span>
        <span>Info</span>
      </div>

      <div ref={scrollRef} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} className="min-h-0 flex-1 overflow-auto">
        {packets.length === 0 ? (
          <p className="px-3 py-6 text-center text-[12px] faint">No packets match this filter.</p>
        ) : (
          <div style={{ height: packets.length * ROW_HEIGHT, position: 'relative' }}>
            <div style={{ transform: `translateY(${first * ROW_HEIGHT}px)` }}>
              {slice.map((p) => {
                const selected = p.index === selectedIndex;
                return (
                  <button
                    key={p.index}
                    data-layer={protocolLayer(p.protocol)}
                    onClick={() => onSelect(p)}
                    style={{ height: ROW_HEIGHT }}
                    className={`grid w-full grid-cols-[52px_84px_150px_150px_74px_58px_1fr] items-center gap-2 px-3 text-left text-[12px] transition-colors focus-ring ${
                      selected ? 'layer-bg' : 'hover:bg-[var(--bg-hover)]'
                    }`}
                  >
                    <span className={`mono tabular-nums ${selected ? 'layer-text' : 'faint'}`}>{p.index}</span>
                    <span className="mono tabular-nums dim">{p.relativeTime.toFixed(6)}</span>
                    <span className="mono truncate" title={p.source}>
                      {p.source}
                    </span>
                    <span className="mono truncate" title={p.destination}>
                      {p.destination}
                    </span>
                    <span className="truncate font-semibold layer-text">{p.protocol}</span>
                    <span className="mono tabular-nums text-right dim">{p.originalLength}</span>
                    <span className="truncate dim" title={p.info}>
                      {p.info}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
