import { useMemo } from 'react';
import type { DissectedPacket, Field, OsiLayer } from '../pcap/types';
import type { LayerView } from '../pcap/osi';
import { flattenFields } from '../pcap/osi';
import type { Highlight } from '../lib/highlight';
import { rangesContain } from '../lib/highlight';
import { toHexByte } from '../pcap/bytes';

const BYTES_PER_ROW = 16;

interface Props {
  packet: DissectedPacket;
  layers: LayerView[];
  highlight: Highlight | null;
  onHighlight: (h: Highlight | null) => void;
  onSelectField: (field: Field) => void;
}

/**
 * The synchronised hex/ASCII pane.
 *
 * Two things happen here that a plain hex dump does not do: every byte is
 * tinted with the colour of the OSI layer that owns it, and hovering a byte
 * finds the most specific dissected field covering it and pushes that up as
 * the shared highlight — so the inspector scrolls to and lights up the field
 * you are pointing at, and vice versa.
 */
export function HexView({ packet, layers, highlight, onHighlight, onSelectField }: Props) {
  const bytes = packet.bytes;

  /** Which OSI layer owns each byte. Higher layers win, since they nest deeper. */
  const byteLayer = useMemo(() => {
    const map = new Uint8Array(bytes.length);
    for (const view of layers) {
      for (const range of view.ranges) {
        const end = Math.min(bytes.length, range.offset + range.length);
        for (let i = Math.max(0, range.offset); i < end; i++) {
          if (view.layer >= map[i]) map[i] = view.layer;
        }
      }
    }
    return map;
  }, [bytes.length, layers]);

  /**
   * For each byte, the field to jump to when the mouse lands on it.
   *
   * Whole-byte fields win over sub-byte flag fields: pointing at the first
   * byte of a MAC address should say "OUI", not "I/G bit". Bit-level fields
   * are still used when nothing else covers the byte, as on the IPv4
   * version/IHL byte where every field is a bit range.
   */
  const byteField = useMemo(() => {
    const whole = new Array<Field | undefined>(bytes.length);
    const any = new Array<Field | undefined>(bytes.length);
    const all = flattenFields(packet.protocols.flatMap((p) => p.fields));
    for (const f of all) {
      if (f.length <= 0 || f.synthetic) continue;
      const end = Math.min(bytes.length, f.offset + f.length);
      for (let i = Math.max(0, f.offset); i < end; i++) {
        if (!any[i] || f.length <= any[i]!.length) any[i] = f;
        if (!f.bits && (!whole[i] || f.length <= whole[i]!.length)) whole[i] = f;
      }
    }
    // Built with Array.from rather than map(): the arrays above are sparse,
    // and map() would skip the holes instead of filling them from `any`.
    return Array.from({ length: bytes.length }, (_, i) => whole[i] ?? any[i]);
  }, [bytes.length, packet.protocols]);

  const rows = Math.ceil(bytes.length / BYTES_PER_ROW) || 1;

  function hoverByte(offset: number): void {
    const f = byteField[offset];
    if (f) {
      onHighlight({
        ranges: [{ offset: f.offset, length: f.length }],
        fieldId: f.id,
        layer: f.layer,
        label: f.name,
        detail: f.value,
      });
    } else {
      onHighlight({
        ranges: [{ offset, length: 1 }],
        layer: (byteLayer[offset] || 1) as OsiLayer,
        label: `Byte ${offset}`,
        detail: `0x${toHexByte(bytes[offset])}`,
      });
    }
  }

  const active = highlight?.ranges ?? [];

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-3 py-2 hairline">
        <div className="flex items-baseline gap-2">
          <h2 className="text-[12px] font-semibold tracking-wide uppercase dim">Hex &amp; ASCII</h2>
          <span className="faint text-[11px]">
            frame {packet.index} &middot; {bytes.length} bytes captured
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {([1, 2, 3, 4, 5, 6, 7] as OsiLayer[]).map((n) => (
            <span
              key={n}
              data-layer={n}
              title={`Layer ${n}`}
              className="h-2 w-2 rounded-[2px]"
              style={{ background: 'var(--layer-color)' }}
            />
          ))}
        </div>
      </div>

      <div className="mono flex-1 overflow-auto px-3 py-2 text-[12px] leading-[1.6]">
        {Array.from({ length: rows }, (_, row) => {
          const start = row * BYTES_PER_ROW;
          return (
            <div key={row} className="flex gap-3 whitespace-pre">
              <span className="faint select-none tabular-nums">{start.toString(16).padStart(4, '0')}</span>

              <span>
                {Array.from({ length: BYTES_PER_ROW }, (_, col) => {
                  const offset = start + col;
                  if (offset >= bytes.length) return <span key={col}>{col === 8 ? '    ' : '   '}</span>;
                  const isActive = rangesContain(active, offset);
                  return (
                    <span key={col}>
                      {col === 8 ? ' ' : ''}
                      <span
                        data-layer={byteLayer[offset] || 1}
                        onMouseEnter={() => hoverByte(offset)}
                        onMouseLeave={() => onHighlight(null)}
                        onClick={() => {
                          const f = byteField[offset];
                          if (f) onSelectField(f);
                        }}
                        className="cursor-pointer rounded-[3px] px-[2px] transition-colors"
                        style={{
                          // Selected bytes invert to the page background so the
                          // digits stay legible instead of washing out.
                          color: isActive ? 'var(--bg)' : 'var(--layer-color)',
                          background: isActive ? 'var(--layer-color)' : undefined,
                          fontWeight: isActive ? 600 : undefined,
                        }}
                      >
                        {toHexByte(bytes[offset])}
                      </span>{' '}
                    </span>
                  );
                })}
              </span>

              <span className="faint select-none">|</span>

              <span>
                {Array.from({ length: BYTES_PER_ROW }, (_, col) => {
                  const offset = start + col;
                  if (offset >= bytes.length) return <span key={col}> </span>;
                  const c = bytes[offset];
                  const printable = c >= 0x20 && c <= 0x7e;
                  const isActive = rangesContain(active, offset);
                  return (
                    <span
                      key={col}
                      data-layer={byteLayer[offset] || 1}
                      onMouseEnter={() => hoverByte(offset)}
                      onMouseLeave={() => onHighlight(null)}
                      onClick={() => {
                        const f = byteField[offset];
                        if (f) onSelectField(f);
                      }}
                      className="cursor-pointer rounded-[2px] transition-colors"
                      style={{
                        color: isActive ? 'var(--bg)' : printable ? 'var(--layer-color)' : 'var(--text-faint)',
                        background: isActive ? 'var(--layer-color)' : undefined,
                        fontWeight: isActive ? 600 : undefined,
                      }}
                    >
                      {printable ? String.fromCharCode(c) : '.'}
                    </span>
                  );
                })}
              </span>
            </div>
          );
        })}
      </div>

      <div className="flex min-h-[34px] items-center gap-2 border-t px-3 py-1.5 hairline">
        {highlight ? (
          <div data-layer={highlight.layer ?? 1} className="flex min-w-0 items-center gap-2">
            <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold layer-bg layer-text">
              L{highlight.layer ?? 1}
            </span>
            <span className="truncate text-[12px]">{highlight.label}</span>
            {highlight.detail && <span className="mono truncate text-[11px] dim">{highlight.detail}</span>}
            <span className="mono shrink-0 text-[11px] faint">
              {highlight.ranges.map((r) => (r.length === 1 ? `@${r.offset}` : `@${r.offset}–${r.offset + r.length - 1}`)).join(', ')}
            </span>
          </div>
        ) : (
          <span className="text-[11px] faint">
            Hover any byte to find its field, or hover a field to find its bytes. Colours are OSI layers.
          </span>
        )}
      </div>
    </div>
  );
}
