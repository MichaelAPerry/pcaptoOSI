import type { Field } from '../pcap/types';
import { LAYER_NAMES } from '../pcap/types';
import { toHexByte } from '../pcap/bytes';

interface Props {
  field: Field | null;
  bytes: Uint8Array;
  onClose: () => void;
}

/**
 * "Teacher Mode" side drawer.
 *
 * Clicking a field pins it here so the explanation stays put while the student
 * goes hunting in the hex pane. It also shows the field's own bytes and, for
 * sub-byte fields, the exact bit positions.
 */
export function FieldDrawer({ field, bytes, onClose }: Props) {
  if (!field) {
    return (
      <div className="border-t px-3 py-2.5 hairline">
        <p className="text-[11.5px] leading-relaxed faint">
          Click any field to pin its explanation here. Hover instead to light up its bytes in the hex pane.
        </p>
      </div>
    );
  }

  const slice: number[] = [];
  for (let i = field.offset; i < Math.min(bytes.length, field.offset + field.length); i++) slice.push(bytes[i]);

  return (
    <div data-layer={field.layer} className="animate-in max-h-[46%] overflow-auto border-t hairline">
      <div className="sticky top-0 flex items-center gap-2 border-b px-3 py-2 hairline" style={{ background: 'var(--bg-panel)' }}>
        <span
          className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px] font-bold"
          style={{ background: 'var(--layer-soft)', color: 'var(--layer-color)' }}
        >
          {field.layer}
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-semibold">{field.name}</div>
          <div className="text-[10px] tracking-wide uppercase faint">
            Layer {field.layer} · {LAYER_NAMES[field.layer]}
          </div>
        </div>
        <button onClick={onClose} className="shrink-0 rounded px-1.5 py-0.5 text-[14px] leading-none faint hover:bg-[var(--bg-hover)] focus-ring" aria-label="Close">
          ×
        </button>
      </div>

      <div className="space-y-2.5 px-3 py-2.5">
        <div>
          <div className="text-[10px] font-semibold tracking-wide uppercase faint">Value</div>
          <div className="mono mt-0.5 text-[12px] break-all layer-text">{field.value}</div>
        </div>

        {slice.length > 0 && (
          <div>
            <div className="text-[10px] font-semibold tracking-wide uppercase faint">
              Bytes {field.offset}–{field.offset + field.length - 1} ({field.length} byte{field.length === 1 ? '' : 's'})
            </div>
            <div className="mono mt-0.5 text-[12px] break-all dim">{slice.map(toHexByte).join(' ')}</div>
            {field.bits && (
              <div className="mono mt-1 text-[11px] faint">
                bits {field.bits.offset}–{field.bits.offset + field.bits.length - 1} of this field
                {'  '}
                {bitDiagram(slice, field.bits.offset, field.bits.length)}
              </div>
            )}
          </div>
        )}

        {field.what && (
          <div>
            <div className="text-[10px] font-semibold tracking-wide uppercase faint">What this field does</div>
            <p className="mt-0.5 text-[12px] leading-relaxed">{field.what}</p>
          </div>
        )}

        {field.why && (
          <div className="rounded border-l-2 px-2.5 py-2 layer-bg layer-border">
            <div className="text-[10px] font-semibold tracking-wide uppercase layer-text">Why this value matters</div>
            <p className="mt-0.5 text-[12px] leading-relaxed dim">{field.why}</p>
          </div>
        )}
      </div>
    </div>
  );
}

/** Render the field's bits, marking the ones this field actually occupies. */
function bitDiagram(slice: number[], bitOffset: number, bitLength: number): string {
  const bits: string[] = [];
  slice.slice(0, 4).forEach((byte, byteIndex) => {
    for (let i = 0; i < 8; i++) {
      const index = byteIndex * 8 + i;
      const inRange = index >= bitOffset && index < bitOffset + bitLength;
      bits.push(inRange ? String((byte >> (7 - i)) & 1) : '.');
    }
    bits.push(' ');
  });
  return bits.join('').trim();
}
